//
// Created by Administrator on 2019/1/29/029.
//

#ifndef MIRROR_BUFFER_H
#define MIRROR_BUFFER_H

#include <stdint.h>
#include "logger.h"

typedef struct mirror_buffer_s mirror_buffer_t;


mirror_buffer_t *mirror_buffer_init( logger_t *logger,
        const unsigned char *aeskey,
        const unsigned char *ecdh_secret);
void mirror_buffer_init_aes(mirror_buffer_t *mirror_buffer, uint64_t streamConnectionID);
void mirror_buffer_decrypt(mirror_buffer_t *raop_mirror, unsigned char* input, unsigned char* output, int datalen);
void mirror_buffer_destroy(mirror_buffer_t *mirror_buffer);
#endif //MIRROR_BUFFER_H
