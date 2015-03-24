#ifndef LOG_H_
#define LOG_H_


#include <stdarg.h>

#if 1

#ifdef ANDROID
#include <android/log.h>
#define TAG "libhook"
#define ALOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define ALOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG, __VA_ARGS__)
#define ASTDERR(...)


#else
#include <stdio.h>
#define ALOGV(...) printf(__VA_ARGS__)
#define ALOGD(...) printf(__VA_ARGS__)
#define ALOGI(...) printf(__VA_ARGS__)
#define ALOGW(...) printf(__VA_ARGS__)
#define ALOGE(...) printf(__VA_ARGS__)
#define ALOGF(...) printf(__VA_ARGS__)
#define ASTDERR(...) fprintf(stderr, __VA_ARGS__)

#endif

#else

#define ALOGV(...)
#define ALOGD(...)
#define ALOGI(...)
#define ALOGW(...)
#define ALOGE(...)
#define ALOGF(...)
#define ASTDERR(...)
#endif

#endif /* LOG_H_ */
