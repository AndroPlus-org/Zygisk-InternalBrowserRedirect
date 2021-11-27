#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include "inject.h"
#include "log.h"
#include "dlfcn.h"
#include <cstdint>
#include <sys/system_properties.h>
#include "elf_util.h"

#define INJECT_CLASS_PATH "com/github/kr328/ibr/remote/Injector"
#define INJECT_METHOD_NAME "inject"
#define INJECT_METHOD_SIGNATURE "(Ljava/lang/String;)V"

static void *dex_data = nullptr;
static size_t dex_data_length = 0u;

static void *runtime_instance = nullptr;

static void (*set_debuggable)(void *, bool) = nullptr;

static void (*set_trusted)(JNIEnv *env, jclass clazz, jobject j_cookie) = nullptr;

static int32_t get_sdk() {
    static int32_t api_level = ({
        char prop_value[PROP_VALUE_MAX];
        __system_property_get("ro.build.version.sdk", prop_value);
        atoi(prop_value);
    });
    return api_level;
}


static int catch_exception(JNIEnv *env) {
    int result = env->ExceptionCheck();

    // check status
    if (result) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    return result;
}

void findSymbol() {
    if (get_sdk() < __ANDROID_API_P__) return;
    SandHook::ElfImg libart("/libart.so");
    if (auto runtime_ptr = libart.getSymbAddress<void **>(
                "_ZN3art7Runtime9instance_E"); runtime_ptr) {
        runtime_instance = *runtime_ptr;
    }
    set_debuggable = libart.getSymbAddress<decltype(set_debuggable)>(
            "_ZN3art7Runtime17SetJavaDebuggableEb");
    set_trusted = libart.getSymbAddress<decltype(set_trusted)>(
            "_ZN3artL18DexFile_setTrustedEP7_JNIEnvP7_jclassP8_jobject");
    if (!runtime_instance || !set_debuggable || !set_trusted) {
        LOGW("Failed to find symbol to bypass hidden API");
        runtime_instance = nullptr;
    }
}

void preloadDex(const char *dex_path) {
    if (dex_data != nullptr) return;
    int fd = open(dex_path, O_RDONLY);
    if (fd < 0) {
        LOGE("Open dex file: %s", strerror(errno));
        return;
    }

    struct stat stat{};

    if (fstat(fd, &stat) < 0) {
        LOGE("fetch size of dex file: %s", strerror(errno));

        close(fd);

        return;
    }


    dex_data = malloc(stat.st_size);
    dex_data_length = stat.st_size;

    auto *ptr = (uint8_t *) dex_data;
    int count = 0;

    while (count < stat.st_size) {
        int r = read(fd, ptr, stat.st_size - count);

        if (r < 0) {
            LOGE("read dex: %s", strerror(errno));

            free(dex_data);
            close(fd);

            dex_data = nullptr;
            dex_data_length = 0;

            return;
        }

        count += r;
        ptr += r;
    }

    close(fd);

}

int load_and_invoke_dex(JNIEnv *env, const char *argument) {
    using namespace std::string_view_literals;
    if (dex_data == nullptr) return 1;
    // get system class loader
    jclass cClassLoader = env->FindClass("java/lang/ClassLoader");
    jmethodID mSystemClassLoader = env->GetStaticMethodID(cClassLoader,
                                                          "getSystemClassLoader",
                                                          "()Ljava/lang/ClassLoader;");
    jobject oSystemClassLoader = env->CallStaticObjectMethod(cClassLoader,
                                                             mSystemClassLoader);

    // load dex
    jobject bufferDex = env->NewDirectByteBuffer(dex_data, dex_data_length);
    jclass cDexClassLoader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID mDexClassLoaderInit = env->GetMethodID(cDexClassLoader, "<init>",
                                                     "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject oDexClassLoader = env->NewObject(cDexClassLoader,
                                             mDexClassLoaderInit,
                                             bufferDex,
                                             oSystemClassLoader);
    if (runtime_instance && "system_server_forked"sv != argument) {
        LOGD("setting our classloader as trusted");

        auto bdc_class = env->FindClass("dalvik/system/BaseDexClassLoader");
        auto path_list_field = env->GetFieldID(bdc_class, "pathList", "Ldalvik/system/DexPathList;");
        auto dpl_class = env->FindClass("dalvik/system/DexPathList");
        auto elements_field = env->GetFieldID(dpl_class, "dexElements",
                                              "[Ldalvik/system/DexPathList$Element;");
        auto element_class = env->FindClass("dalvik/system/DexPathList$Element");
        auto dex_file_field = env->GetFieldID(element_class, "dexFile", "Ldalvik/system/DexFile;");
        auto dex_file_class = env->FindClass("dalvik/system/DexFile");
        auto cookie_field = env->GetFieldID(dex_file_class, "mCookie", "Ljava/lang/Object;");

        auto path_list = env->GetObjectField(oDexClassLoader, path_list_field);
        auto elements = (jobjectArray) env->GetObjectField(path_list, elements_field);
        auto len = env->GetArrayLength(elements);
        set_debuggable(runtime_instance, true);
        for (int i = 0; i < len; ++i) {
            auto element = env->GetObjectArrayElement(elements, i);
            auto dex_file = env->GetObjectField(element, dex_file_field);
            auto cookie = env->GetObjectField(dex_file, cookie_field);
            set_trusted(env, dex_file_class, cookie);
        }
        set_debuggable(runtime_instance, false);
        LOGD("our classloader is now trusted");
    }

    if (catch_exception(env)) return 1;

    // get loaded dex inject method
    jmethodID mFindClass = env->GetMethodID(cDexClassLoader, "loadClass",
                                            "(Ljava/lang/String;Z)Ljava/lang/Class;");
    jstring sInjectClassName = env->NewStringUTF(INJECT_CLASS_PATH);
    auto cInject = (jclass) env->CallObjectMethod(oDexClassLoader,
                                                  mFindClass, sInjectClassName, (jboolean) 0);

    if (catch_exception(env)) return 1;

    // find method
    jmethodID mLoaded = env->GetStaticMethodID(cInject, INJECT_METHOD_NAME,
                                               INJECT_METHOD_SIGNATURE);

    if (catch_exception(env)) return 1;

    // invoke inject method
    jstring stringArgument = env->NewStringUTF(argument);

    env->CallStaticVoidMethod(cInject, mLoaded, stringArgument);

    return catch_exception(env);
}

