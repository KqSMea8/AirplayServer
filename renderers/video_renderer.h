//
// Created by Florian Draschbacher on 2019/04/22
//

/* 
 * H264 renderer using OpenMAX for hardware accelerated decoding
 * on the Raspberry Pi. 
 * Based on the hello_video sample from the Raspberry Pi project.
*/

#ifndef VIDEO_RENDERER_H
#define VIDEO_RENDERER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "../lib/logger.h"

typedef struct video_renderer_s video_renderer_t;

video_renderer_t *video_renderer_init( logger_t *logger );
void video_renderer_render_buffer(video_renderer_t *renderer, unsigned char* data, int datalen);
void video_renderer_flush(video_renderer_t *renderer);
void video_renderer_destroy(video_renderer_t *renderer);

#ifdef __cplusplus
}
#endif

#endif //VIDEO_RENDERER_H
