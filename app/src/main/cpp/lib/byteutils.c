//
// Created by Administrator on 2019/1/10/010.
//

#include <time.h>
#include "byteutils.h"

int byteutils_get_int(unsigned char* b, int offset) {
    return ((b[offset + 3] & 0xff) << 24) | ((b[offset + 2] & 0xff) << 16) | ((b[offset + 1] & 0xff) << 8) | (b[offset] & 0xff);
}

short byteutils_get_short(unsigned char* b, int offset) {
    return (short) ((b[offset + 1] << 8) | (b[offset] & 0xff));
}

float byteutils_get_float(unsigned char* b, int offset) {
    //unsigned char tmp[4] = {b[offset + 3], b[offset + 2], b[offset + 1], b[offset]};
    return *((float *)(b + offset));
}


uint64_t byteutils_get_int2(unsigned char* b, int offset) {
    return ((uint64_t)(b[offset + 3] & 0xff) << 24) | ((uint64_t)(b[offset + 2] & 0xff) << 16) | ((uint64_t)(b[offset + 1] & 0xff) << 8) | ((uint64_t)b[offset] & 0xff);
}

uint64_t byteutils_get_long(unsigned char* b, int offset) {
    return (byteutils_get_int2(b, offset + 4)) << 32 | byteutils_get_int2(b, offset);
}

//s -> us
uint64_t ntptopts(uint64_t ntp) {
    return (((ntp >> 32) & 0xffffffff)* 1000000) + ((ntp & 0xffffffff) * 1000 * 1000 / INT_32_MAX) ;
}

uint64_t byteutils_read_int(unsigned char* b, int offset) {
    return ((uint64_t)b[offset]  << 24) | ((uint64_t)b[offset + 1]  << 16) | ((uint64_t)b[offset + 2] << 8) | ((uint64_t)b[offset + 3]  << 0);
}
//s->us
uint64_t byteutils_read_timeStamp(unsigned char* b, int offset) {
    return (byteutils_read_int(b, offset) * 1000000) + ((byteutils_read_int(b, offset + 4) * 1000000) / INT_32_MAX);
}
// us time to ntp
void byteutils_put_timeStamp(unsigned char* b, int offset, uint64_t time) {

    // time= ms
    uint64_t seconds = time / 1000000L;
    uint64_t microseconds = time - seconds * 1000000L;
    seconds += OFFSET_1900_TO_1970;

    // write seconds in big endian format
    b[offset++] = (uint8_t)(seconds >> 24);
    b[offset++] = (uint8_t)(seconds >> 16);
    b[offset++] = (uint8_t)(seconds >> 8);
    b[offset++] = (uint8_t)(seconds >> 0);

    uint64_t fraction = microseconds * 0x100000000L / 1000000L;
    // write fraction in big endian format
    b[offset++] = (uint8_t)(fraction >> 24);
    b[offset++] = (uint8_t)(fraction >> 16);
    b[offset++] = (uint8_t)(fraction >> 8);
    // low order bits should be random data
    b[offset++] = (uint8_t)(fraction >> 0);
    //b[offset++] = (Math.random() * 255.0);
}

uint64_t now_us() {
    struct timespec time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time);
    return (uint64_t)time.tv_sec * 10000000L + (uint64_t)(time.tv_nsec / 1000);
}
