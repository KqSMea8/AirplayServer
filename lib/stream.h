//
// Created by Administrator on 2019/1/31/031.
//

#ifndef AIRPLAYSERVER_STREAM_H
#define AIRPLAYSERVER_STREAM_H

#include <stdint.h>

typedef struct {
    int nGOPIndex;
    int frame_type;
    int nFramePOC;
    unsigned char *data;
    int data_len;
    unsigned int nTimeStamp;
    uint64_t pts;
} h264_decode_struct;

typedef struct {
    unsigned short *data;
    int data_len;
    unsigned int pts;
} pcm_data_struct;
#endif //AIRPLAYSERVER_STREAM_H
