//
// Created by Administrator on 2019/1/29/029.
//

#ifndef AIRPLAYSERVER_LOG_H
#define AIRPLAYSERVER_LOG_H

#include <cstdio>

#define TAG "raop"
#define LEVEL_ERROR 0
#define LEVEL_WARN 1
#define LEVEL_INFO 2
#define LEVEL_DEBUG 3
#define LEVEL_VERBOSE 4

void log(int level, const char* format, ...) {
    va_list vargs;
    va_start(vargs, format);
    vprintf(format, vargs);
    va_end(vargs);
}

#define LOGV(...) log(LEVEL_VERBOSE, __VA_ARGS__)
#define LOGD(...) log(LEVEL_DEBUG, __VA_ARGS__)
#define LOGI(...) log(LEVEL_INFO, __VA_ARGS__)
#define LOGW(...) log(LEVEL_WARN, __VA_ARGS__)
#define LOGE(...) log(LEVEL_ERROR, __VA_ARGS__)


#endif //AIRPLAYSERVER_LOG_H
