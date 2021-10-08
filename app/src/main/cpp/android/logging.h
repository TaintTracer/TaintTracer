#pragma once

#include <android/log.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

//TODO: Redirect stdio to __android_log_print calls
//TODO: Make logging work with msg as non-char const

#define LOG_TAG "TaintTracer"

#define LOG_LEVEL_V

#ifndef ANDROID_LOG_FN
#define ANDROID_LOG_FN android_log_print_wrapper
#endif

#if defined(LOG_LEVEL_V)
#define  LOGV(msg, ...)  ANDROID_LOG_FN(ANDROID_LOG_VERBOSE, LOG_TAG, msg "\n", ##__VA_ARGS__)
#else
#define  LOGV(msg, ...)
#endif
#if defined(LOG_LEVEL_V) || defined(LOG_LEVEL_D)
#define  LOGD(msg, ...)  ANDROID_LOG_FN(ANDROID_LOG_DEBUG, LOG_TAG, msg "\n", ##__VA_ARGS__)
#else
#define  LOGD(msg, ...)
#endif

#if defined(LOG_LEVEL_V) || defined(LOG_LEVEL_D) || defined(LOG_LEVEL_I)
#define  LOGI(msg, ...)  ANDROID_LOG_FN(ANDROID_LOG_INFO, LOG_TAG, msg "\n", ##__VA_ARGS__)
#else
#define  LOGI(msg, ...)
#endif


#if defined(LOG_LEVEL_V) || defined(LOG_LEVEL_D) || defined(LOG_LEVEL_I) || defined(LOG_LEVEL_W)
#define  LOGW(msg, ...)  ANDROID_LOG_FN(ANDROID_LOG_WARN, LOG_TAG, msg "\n", ##__VA_ARGS__)
#else
#define  LOGW(msg, ...)
#endif

#if defined(LOG_LEVEL_V) || defined(LOG_LEVEL_D) || defined(LOG_LEVEL_I) || defined(LOG_LEVEL_W) || defined(LOG_LEVEL_E)
#define  LOGE(msg, ...)  ANDROID_LOG_FN(ANDROID_LOG_ERROR, LOG_TAG, msg "\n", ##__VA_ARGS__)
#define  LOGEN(msg, ...) ANDROID_LOG_FN(ANDROID_LOG_ERROR, LOG_TAG, msg, ##__VA_ARGS__)
#else
#define  LOGE(msg, ...)
#define  LOGEN(msg, ...)
#endif

/*
#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION __FILE__ " : " S2(__LINE__) " : "
 */

#define TRY(fn, msg, ...) ({ auto res = fn; if (res == -1) { LOGE("[%s:%d] " msg, __FILE__, __LINE__, ##__VA_ARGS__); abort(); } res; })
#define TRYSYSFATAL(fn) TRY(fn, "errno %d: %s", errno, strerror(errno))

#include <stdio.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif
void android_log_setup(const char *path);
int android_log_print_wrapper(int prio, const char* tag, const char* fmt, ...);
/**
 * Printf wrapper around __android_log_* that only prints using the log API when a whole line
 * should be printed.
 */
int android_printf(const char *format, ...);
int android_printf_v(const char *format, ...);
void android_hexdump(const unsigned char *ptr, size_t size, size_t label_offset = 0);
#ifdef __cplusplus
}
#endif
