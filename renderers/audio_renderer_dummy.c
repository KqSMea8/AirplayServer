/**
 * RPiPlay - An open-source AirPlay mirroring server for Raspberry Pi
 * Copyright (C) 2019 Florian Draschbacher
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include "audio_renderer.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

struct audio_renderer_s {
    logger_t *logger;
};

audio_renderer_t *audio_renderer_init(logger_t *logger, video_renderer_t *video_renderer, audio_device_t device, bool low_latency) {
    audio_renderer_t *renderer;
    renderer = calloc(1, sizeof(audio_renderer_t));
    if (!renderer) {
        return NULL;
    }
    renderer->logger = logger;
    return renderer;
}

void audio_renderer_start(audio_renderer_t *renderer) {
}

void audio_renderer_render_buffer(audio_renderer_t *renderer, raop_ntp_t *ntp, unsigned char* data, int data_len, uint64_t pts) {
}

void audio_renderer_set_volume(audio_renderer_t *renderer, float volume) {
}

void audio_renderer_flush(audio_renderer_t *renderer) {
}

void audio_renderer_destroy(audio_renderer_t *renderer) {
    if (renderer) {
        free(renderer);
    }
}
