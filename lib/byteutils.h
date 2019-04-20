//
// Created by Administrator on 2019/1/10/010.
//

#ifndef AIRPLAYSERVER_BYTEUTILS_H
#define AIRPLAYSERVER_BYTEUTILS_H
#include <stdint.h>
#define INT_32_MAX 0x100000000
                  //0x100000000
//4294967296
#define OFFSET_1900_TO_1970 2208988800
int byteutils_get_int(unsigned char* b, int offset);
short byteutils_get_short(unsigned char* b, int offset);
float byteutils_get_float(unsigned char* b, int offset);
uint64_t byteutils_get_long(unsigned char* b, int offset);

uint64_t ntptopts(uint64_t ntp);

uint64_t byteutils_read_int(unsigned char* b, int offset);
uint64_t byteutils_read_timeStamp(unsigned char* b, int offset);
void byteutils_put_timeStamp(unsigned char* b, int offset, uint64_t time);

uint64_t now_us();

#endif //AIRPLAYSERVER_BYTEUTILS_H
