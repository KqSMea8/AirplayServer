//
// Created by Administrator on 2019/1/31/031.
//

#ifndef AIRPLAYSERVER_STREAM_H
#define AIRPLAYSERVER_STREAM_H

#include <stdint.h>

typedef struct {
    int n_gop_index;
    int frame_type;
    int n_frame_poc;
    unsigned char *data;
    int data_len;
    unsigned int n_time_stamp;
    uint64_t pts;
} h264_decode_struct;

typedef struct {
    unsigned short *data;
    int data_len;
} aac_decode_struct;

#endif //AIRPLAYSERVER_STREAM_H
