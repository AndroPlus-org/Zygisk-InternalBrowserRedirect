#include <cstdio>
#include <jni.h>
#include <dlfcn.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include <sys/system_properties.h>
#include <zygisk.hpp>
#include <string_view>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/mount.h>

#include "elf_util.h"
#include "log.h"

#define DEX_PATH    "framework/ibr.dex"
#define RULES_PATH  "/data/misc/internal_browser_redirect/userdata/rules.%s.json"
#define INJECT_CLASS_PATH "com/github/kr328/ibr/remote/Injector"
#define INJECT_METHOD_NAME "inject"
#define INJECT_METHOD_SIGNATURE "(Ljava/lang/String;)V"

namespace ibr {
    using namespace std::string_view_literals;
    namespace {
        ssize_t xsendmsg(int sockfd, const struct msghdr *msg, int flags) {
            int sent = sendmsg(sockfd, msg, flags);
            if (sent < 0) {
                PLOGE("sendmsg");
            }
            return sent;
        }

        ssize_t xrecvmsg(int sockfd, struct msghdr *msg, int flags) {
            int rec = recvmsg(sockfd, msg, flags);
            if (rec < 0) {
                PLOGE("recvmsg");
            }
            return rec;
        }

        // Read exact same size as count
        ssize_t xxread(int fd, void *buf, size_t count) {
            size_t read_sz = 0;
            ssize_t ret;
            do {
                ret = read(fd, (std::byte *) buf + read_sz, count - read_sz);
                if (ret < 0) {
                    if (errno == EINTR)
                        continue;
                    PLOGE("read");
                    return ret;
                }
                read_sz += ret;
            } while (read_sz != count && ret != 0);
            if (read_sz != count) {
                PLOGE("read (%zu != %zu)", count, read_sz);
            }
            return read_sz;
        }

        // Write exact same size as count
        ssize_t xwrite(int fd, const void *buf, size_t count) {
            size_t write_sz = 0;
            ssize_t ret;
            do {
                ret = write(fd, (std::byte *) buf + write_sz, count - write_sz);
                if (ret < 0) {
                    if (errno == EINTR)
                        continue;
                    PLOGE("write");
                    return ret;
                }
                write_sz += ret;
            } while (write_sz != count && ret != 0);
            if (write_sz != count) {
                PLOGE("write (%zu != %zu)", count, write_sz);
            }
            return write_sz;
        }

        int send_fds(int sockfd, void *cmsgbuf, size_t bufsz, const int *fds, int cnt) {
            iovec iov = {
                    .iov_base = &cnt,
                    .iov_len  = sizeof(cnt),
            };
            msghdr msg = {
                    .msg_iov        = &iov,
                    .msg_iovlen     = 1,
            };

            if (cnt) {
                msg.msg_control = cmsgbuf;
                msg.msg_controllen = bufsz;
                cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_len = CMSG_LEN(sizeof(int) * cnt);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;

                memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * cnt);
            }

            return xsendmsg(sockfd, &msg, 0);
        }

        int send_fd(int sockfd, int fd) {
            if (fd < 0) {
                return send_fds(sockfd, nullptr, 0, nullptr, 0);
            }
            char cmsgbuf[CMSG_SPACE(sizeof(int))];
            return send_fds(sockfd, cmsgbuf, sizeof(cmsgbuf), &fd, 1);
        }

        void *recv_fds(int sockfd, char *cmsgbuf, size_t bufsz, int cnt) {
            iovec iov = {
                    .iov_base = &cnt,
                    .iov_len  = sizeof(cnt),
            };
            msghdr msg = {
                    .msg_iov        = &iov,
                    .msg_iovlen     = 1,
                    .msg_control    = cmsgbuf,
                    .msg_controllen = bufsz
            };

            xrecvmsg(sockfd, &msg, MSG_WAITALL);
            cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

            if (msg.msg_controllen != bufsz ||
                cmsg == nullptr ||
                cmsg->cmsg_len != CMSG_LEN(sizeof(int) * cnt) ||
                cmsg->cmsg_level != SOL_SOCKET ||
                cmsg->cmsg_type != SCM_RIGHTS) {
                return nullptr;
            }

            return CMSG_DATA(cmsg);
        }

        int recv_fd(int sockfd) {
            char cmsgbuf[CMSG_SPACE(sizeof(int))];

            void *data = recv_fds(sockfd, cmsgbuf, sizeof(cmsgbuf), 1);
            if (data == nullptr)
                return -1;

            int result;
            memcpy(&result, data, sizeof(int));
            return result;
        }

        int read_int(int fd) {
            int val;
            if (xxread(fd, &val, sizeof(val)) != sizeof(val))
                return -1;
            return val;
        }

        void write_int(int fd, int val) {
            if (fd < 0) return;
            xwrite(fd, &val, sizeof(val));
        }
    }

    class ZygiskModule : public zygisk::ModuleBase {
        JNIEnv *env_ = nullptr;
        zygisk::Api *api_ = nullptr;

        void *dex_data_ = nullptr;
        size_t dex_size_ = 0u;

        void *runtime_instance_ = nullptr;

        void (*set_debuggable_)(void *, bool) = nullptr;

        void (*set_trusted_)(JNIEnv *env, jclass clazz, jobject j_cookie) = nullptr;

        static int32_t get_sdk() {
            static int32_t api_level = ({
                char prop_value[PROP_VALUE_MAX];
                __system_property_get("ro.build.version.sdk", prop_value);
                atoi(prop_value);
            });
            return api_level;
        }

        void findSymbol() {
            if (get_sdk() < __ANDROID_API_P__) return;
            SandHook::ElfImg libart("/libart.so");
            if (auto runtime_ptr = libart.getSymbAddress<void **>(
                        "_ZN3art7Runtime9instance_E"); runtime_ptr) {
                runtime_instance_ = *runtime_ptr;
            }
            set_debuggable_ = libart.getSymbAddress<decltype(set_debuggable_)>(
                    "_ZN3art7Runtime17SetJavaDebuggableEb");
            set_trusted_ = libart.getSymbAddress<decltype(set_trusted_)>(
                    "_ZN3artL18DexFile_setTrustedEP7_JNIEnvP7_jclassP8_jobject");
            if (!runtime_instance_ || !set_debuggable_ || !set_trusted_) {
                LOGW("Failed to find symbol to bypass hidden API");
                runtime_instance_ = nullptr;
            }
        }

        void onLoad(zygisk::Api *api, JNIEnv *env) override {
            env_ = env;
            api_ = api;
        }

        int catch_exception() {
            int result = env_->ExceptionCheck();

            // check status
            if (result) {
                env_->ExceptionDescribe();
                env_->ExceptionClear();
            }

            return result;
        }

        int load_and_invoke_dex(const char *argument) {
            using namespace std::string_view_literals;
            if (!dex_data_) return 1;
            // get system class loader
            jclass cClassLoader = env_->FindClass("java/lang/ClassLoader");
            jmethodID mSystemClassLoader = env_->GetStaticMethodID(cClassLoader,
                                                                   "getSystemClassLoader",
                                                                   "()Ljava/lang/ClassLoader;");
            jobject oSystemClassLoader = env_->CallStaticObjectMethod(cClassLoader,
                                                                      mSystemClassLoader);

            // load dex
            jobject bufferDex = env_->NewDirectByteBuffer(dex_data_, dex_size_);
            dex_data_ = nullptr;
            dex_size_ = 0u;
            jclass cDexClassLoader = env_->FindClass("dalvik/system/InMemoryDexClassLoader");
            jmethodID mDexClassLoaderInit = env_->GetMethodID(cDexClassLoader, "<init>",
                                                              "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
            jobject oDexClassLoader = env_->NewObject(cDexClassLoader,
                                                      mDexClassLoaderInit,
                                                      bufferDex,
                                                      oSystemClassLoader);
            munmap(dex_data_, dex_size_);
            findSymbol();
            if (runtime_instance_ && "system_server_forked"sv != argument) {
                LOGD("setting our classloader as trusted");

                auto bdc_class = env_->FindClass("dalvik/system/BaseDexClassLoader");
                auto path_list_field = env_->GetFieldID(bdc_class, "pathList",
                                                        "Ldalvik/system/DexPathList;");
                auto dpl_class = env_->FindClass("dalvik/system/DexPathList");
                auto elements_field = env_->GetFieldID(dpl_class, "dexElements",
                                                       "[Ldalvik/system/DexPathList$Element;");
                auto element_class = env_->FindClass("dalvik/system/DexPathList$Element");
                auto dex_file_field = env_->GetFieldID(element_class, "dexFile",
                                                       "Ldalvik/system/DexFile;");
                auto dex_file_class = env_->FindClass("dalvik/system/DexFile");
                auto cookie_field = env_->GetFieldID(dex_file_class, "mCookie",
                                                     "Ljava/lang/Object;");

                auto path_list = env_->GetObjectField(oDexClassLoader, path_list_field);
                auto elements = (jobjectArray) env_->GetObjectField(path_list, elements_field);
                auto len = env_->GetArrayLength(elements);
                set_debuggable_(runtime_instance_, true);
                for (int i = 0; i < len; ++i) {
                    auto element = env_->GetObjectArrayElement(elements, i);
                    auto dex_file = env_->GetObjectField(element, dex_file_field);
                    auto cookie = env_->GetObjectField(dex_file, cookie_field);
                    set_trusted_(env_, dex_file_class, cookie);
                }
                set_debuggable_(runtime_instance_, false);
                LOGD("our classloader is now trusted");
            }

            if (catch_exception()) return 1;

            // get loaded dex inject method
            jmethodID mFindClass = env_->GetMethodID(cDexClassLoader, "loadClass",
                                                     "(Ljava/lang/String;Z)Ljava/lang/Class;");
            jstring sInjectClassName = env_->NewStringUTF(INJECT_CLASS_PATH);
            auto cInject = (jclass) env_->CallObjectMethod(oDexClassLoader,
                                                           mFindClass, sInjectClassName,
                                                           (jboolean) 0);

            if (catch_exception()) return 1;

            // find method
            jmethodID mLoaded = env_->GetStaticMethodID(cInject, INJECT_METHOD_NAME,
                                                        INJECT_METHOD_SIGNATURE);

            if (catch_exception()) return 1;

            // invoke inject method
            jstring stringArgument = env_->NewStringUTF(argument);

            env_->CallStaticVoidMethod(cInject, mLoaded, stringArgument);

            return catch_exception();
        }

        void preload_dex(std::string_view pkg_name) {
            int companion = api_->connectCompanion();

            if (companion > 0) {
                auto module_dir = api_->getModuleDir();
                send_fd(companion, module_dir);
                write_int(companion, static_cast<int>(pkg_name.size()));
                xwrite(companion, pkg_name.data(), pkg_name.size());
                bool inject = read_int(companion);
                if (inject) {
                    auto dex_fd = recv_fd(companion);
                    struct stat s{};
                    fstat(dex_fd, &s);
                    dex_size_ = s.st_size;
                    dex_data_ = mmap(nullptr, dex_size_, PROT_READ, MAP_PRIVATE, dex_fd, 0);
                    if (dex_data_ == MAP_FAILED) {
                        PLOGE("map failed");
                        dex_data_ = nullptr;
                    }
                    close(dex_fd);
                }
                close(companion);
            } else {
                LOGE("failed to connect to companion");
            }
        }

        void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
            char buff[256] = {0};

            if (args->app_data_dir) {
                const char *app_data_dir = env_->GetStringUTFChars(args->app_data_dir, nullptr);
                int user = 0;
                while (app_data_dir) {
                    // /data/user/<user_id>/<package>
                    if (sscanf(app_data_dir, "/data/%*[^/]/%d/%s", &user, buff) == 2)
                        break;

                    // /mnt/expand/<id>/user/<user_id>/<package>
                    if (sscanf(app_data_dir, "/mnt/expand/%*[^/]/%*[^/]/%d/%s", &user,
                               buff) == 2)
                        break;

                    // /data/data/<package>
                    if (sscanf(app_data_dir, "/data/%*[^/]/%s", buff) == 1)
                        break;

                    buff[0] = '\0';
                    break;
                }
                env_->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
            }
            std::string_view pkg_name = buff;

            if (!pkg_name.empty()) {
                preload_dex(pkg_name);
            }

            LOGD("should hook %s: %d", pkg_name.data(), dex_data_ != nullptr);

            using namespace std::string_view_literals;
            if (!dex_data_) {
                api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            }
        }

        void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
            if (dex_data_) {
                load_and_invoke_dex("app_forked");
            }
        }

        void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
            preload_dex("system_server");
        }

        void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override {
            if (dex_data_) {
                load_and_invoke_dex("system_server_forked");
            }
        }
    };

    void CompanionEntry(int client) {
        auto module_dir = recv_fd(client);
        static int dex_fd = openat(module_dir, DEX_PATH, O_RDONLY | O_CLOEXEC);
        auto len = read_int(client);
        char package_name[256] = {0};
        xxread(client, package_name, len);
        char path[PATH_MAX] = {};
        snprintf(path, PATH_MAX, RULES_PATH, package_name);
        if (access(path, F_OK) == 0 || strcmp(package_name, "system_server") == 0) {
            write_int(client, 1);
            send_fd(client, dex_fd);
        } else {
            write_int(client, 0);
        }
    }
}

REGISTER_ZYGISK_MODULE(ibr::ZygiskModule);

REGISTER_ZYGISK_COMPANION(ibr::CompanionEntry);
