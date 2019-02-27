//
// Created by Administrator on 2019/1/29/029.
//

#ifndef AIRPLAYSERVER_LOG_H
#define AIRPLAYSERVER_LOG_H
#include <android/log.h>

#define TAG "raop"

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG ,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG ,__VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG ,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG ,__VA_ARGS__)


#endif //AIRPLAYSERVER_LOG_H
