//
// Created by Florian Draschbacher on 2019/04/22
//

#ifndef VIDEO_RENDERER_H
#define VIDEO_RENDERER_H

#include <stdint.h>
#include "logger.h"

typedef struct video_renderer_s video_renderer_t;


video_renderer_t *video_renderer_init( logger_t *logger );
void video_renderer_render_buffer(video_renderer_t *renderer, unsigned char* data, int datalen);
void video_renderer_flush(video_renderer_t *renderer);
void video_renderer_destroy(video_renderer_t *renderer);
#endif //VIDEO_RENDERER_H
