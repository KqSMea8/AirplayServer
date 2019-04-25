//
// Created by Florian Draschbacher on 2019/04/24
//

/* 
 * AAC renderer using fdk-aac for decoding and OpenMAX for rendering
*/

#ifndef AUDIO_RENDERER_H
#define AUDIO_RENDERER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "../lib/logger.h"

typedef enum audio_device_e { AUDIO_DEVICE_HDMI, AUDIO_DEVICE_ANALOG } audio_device_t;

typedef struct audio_renderer_s audio_renderer_t;

audio_renderer_t *audio_renderer_init(logger_t *logger, audio_device_t device);
void audio_renderer_render_buffer(audio_renderer_t *renderer, unsigned char* data, int datalen);
void audio_renderer_flush(audio_renderer_t *renderer);
void audio_renderer_destroy(audio_renderer_t *renderer);

#ifdef __cplusplus
}
#endif

#endif //AUDIO_RENDERER_H
