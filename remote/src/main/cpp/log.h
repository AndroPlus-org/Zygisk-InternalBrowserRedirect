#pragma once

#include <android/log.h>

#define TAG "InternalBrowserRedirect"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO  ,TAG ,__VA_ARGS__)
#ifndef NDEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG ,TAG ,__VA_ARGS__)
#else
#define LOGD(...)
#endif
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR ,TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN  ,TAG ,__VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
