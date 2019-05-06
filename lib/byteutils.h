/*
 * Copyright (c) 2019 dsafa22, All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

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
uint64_t byteutils_read_time_stamp(unsigned char *b, int offset);
void byteutils_put_time_stamp(unsigned char *b, int offset, uint64_t time);

uint64_t now_us();

#endif //AIRPLAYSERVER_BYTEUTILS_H
