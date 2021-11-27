#include <cstdio>
#include <jni.h>
#include <dlfcn.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include <sys/system_properties.h>
#include <riru.h>

#include "log.h"
#include "inject.h"

#define DEX_PATH    "/framework/ibr.dex"
#define RULES_PATH  "/data/misc/internal_browser_redirect/userdata/rules.%s.json"
#define SERVICE_STATUE_KEY "sys.ibr.status"

static int enable_inject;

int *allow_unload = nullptr;
const char *magisk_path = nullptr;

static void on_app_fork(JNIEnv *env, jstring jAppDataDir) {
    char path_buffer[1024];
    char package_name[256] = {0};

    if (jAppDataDir) {
        const char *appDataDir = env->GetStringUTFChars(jAppDataDir, NULL);
        int user = 0;
        while (appDataDir) {
            // /data/user/<user_id>/<package>
            if (sscanf(appDataDir, "/data/%*[^/]/%d/%s", &user, package_name) == 2)
                break;

            // /mnt/expand/<id>/user/<user_id>/<package>
            if (sscanf(appDataDir, "/mnt/expand/%*[^/]/%*[^/]/%d/%s", &user, package_name) == 2)
                break;

            // /data/data/<package>
            if (sscanf(appDataDir, "/data/%*[^/]/%s", package_name) == 1)
                break;

            package_name[0] = '\0';
            break;
        }
        env->ReleaseStringUTFChars(jAppDataDir, appDataDir);
    }

    sprintf(path_buffer, RULES_PATH, package_name);

    enable_inject = access(path_buffer, F_OK) == 0;
    LOGD("should hook %s: %d", package_name, enable_inject);
    if (allow_unload) *allow_unload = true;
}

static void nativeForkAndSpecializePre(
        JNIEnv *env, jclass clazz, jint *_uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jintArray *fdsToClose, jintArray *fdsToIgnore, jboolean *is_child_zygote,
        jstring *instructionSet, jstring *appDataDir, jboolean *isTopApp,
        jobjectArray *pkgDataInfoList,
        jobjectArray *whitelistedDataInfoList, jboolean *bindMountAppDataDirs,
        jboolean *bindMountAppStorageDirs) {
    on_app_fork(env, *appDataDir);
}

static void nativeForkAndSpecializePost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0 && enable_inject) {
        load_and_invoke_dex(env, "app_forked");
    }
}

static void nativeForkSystemServerPost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0) {
        __system_property_set(SERVICE_STATUE_KEY, "system_server_forked");
        load_and_invoke_dex(env, "system_server_forked");
    }
}

static void onModuleLoaded() {
    LOGI("welcome to ibr");
    char tmp[PATH_MAX] = {'\0'};
    strcat(tmp, magisk_path);
    strcat(tmp, DEX_PATH);
    preloadDex(tmp);
    findSymbol();
}

static RiruVersionedModuleInfo module = {
        .moduleApiVersion = RIRU_MODULE_API_VERSION,
        .moduleInfo = {
                .supportHide = true,
                .version = 1,
                .versionName = RIRU_MODULE_VERSION_NAME,
                .onModuleLoaded = onModuleLoaded,
                .forkAndSpecializePre = nativeForkAndSpecializePre,
                .forkAndSpecializePost = nativeForkAndSpecializePost,
                .forkSystemServerPre = nullptr,
                .forkSystemServerPost = nativeForkSystemServerPost,
                .specializeAppProcessPre = nullptr,
                .specializeAppProcessPost = nullptr,
        }
};

RIRU_EXPORT RiruVersionedModuleInfo *init(Riru *riru) {
    if (riru->riruApiVersion < RIRU_MODULE_API_VERSION) return nullptr;
    allow_unload = riru->allowUnload;
    magisk_path = strdup(riru->magiskModulePath);
    return &module;
}
