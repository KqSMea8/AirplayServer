/**
 *  Copyright (C) 2011-2012  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "raop_buffer.h"
#include "raop_rtp.h"

#include "crypto.h"
#include "compat.h"
#include "stream.h"

struct raop_buffer_s {
    logger_t *logger;
    /* Key and IV used for decryption */
    unsigned char aeskey[RAOP_AESKEY_LEN];
    unsigned char aesiv[RAOP_AESIV_LEN];

    // Last received sequence number
    unsigned short last_seqnum;
    bool first_packet;
};

void
raop_buffer_init_key_iv(raop_buffer_t *raop_buffer,
                     const unsigned char *aeskey,
                     const unsigned char *aesiv,
                     const unsigned char *ecdh_secret)
{

    // Initialization key
    unsigned char eaeskey[64];
    memcpy(eaeskey, aeskey, 16);

    sha_ctx_t *ctx = sha_init();
    sha_update(ctx, eaeskey, 16);
    sha_update(ctx, ecdh_secret, 32);
    sha_final(ctx, eaeskey, NULL);
    sha_destroy(ctx);
    
    memcpy(raop_buffer->aeskey, eaeskey, 16);
    memcpy(raop_buffer->aesiv, aesiv, RAOP_AESIV_LEN);
#ifdef DUMP_AUDIO
    if (file_keyiv != NULL) {
        fwrite(raop_buffer->aeskey, 16, 1, file_keyiv);
        fwrite(raop_buffer->aesiv, 16, 1, file_keyiv);
        fclose(file_keyiv);
    }
#endif
}

raop_buffer_t *
raop_buffer_init(logger_t *logger,
                 const unsigned char *aeskey,
                 const unsigned char *aesiv,
                 const unsigned char *ecdh_secret)
{
    raop_buffer_t *raop_buffer;
    assert(aeskey);
    assert(aesiv);
    assert(ecdh_secret);
    raop_buffer = calloc(1, sizeof(raop_buffer_t));
    if (!raop_buffer) {
        return NULL;
    }
    raop_buffer->logger = logger;
    raop_buffer_init_key_iv(raop_buffer, aeskey, aesiv, ecdh_secret);

    raop_buffer->last_seqnum = 0;
    raop_buffer->first_packet = true;    

    return raop_buffer;
}

void
raop_buffer_destroy(raop_buffer_t *raop_buffer)
{
	if (raop_buffer) {
		free(raop_buffer);
	}
#ifdef DUMP_AUDIO
    if (file_aac != NULL) {
        fclose(file_aac);
    }
    if (file_source != NULL) {
        fclose(file_source);
    }
#endif

}

static short
seqnum_cmp(unsigned short s1, unsigned short s2)
{
	return (s1 - s2);
}

#define DUMP_AUDIO

#ifdef DUMP_AUDIO
static FILE* file_aac = NULL;
static FILE* file_source = NULL;
static FILE* file_keyiv = NULL;
#endif


int
raop_buffer_decrypt(raop_buffer_t *raop_buffer, unsigned char *data, unsigned char* output, unsigned int datalen, unsigned int *outputlen)
{
    assert(raop_buffer);
    int encryptedlen;
#ifdef DUMP_AUDIO
    if (file_aac == NULL) {
        file_aac = fopen("/home/pi/Airplay.aac", "wb");
        file_source = fopen("/home/pi/Airplay.source", "wb");
        file_keyiv = fopen("/home/pi/Airplay.keyiv", "wb");
    }
#endif

    /* Check packet data length is valid */
    if (datalen < 12 || datalen > RAOP_PACKET_LEN) {
        return -1;
    }
    unsigned short seqnum = (data[2] << 8) | data[3];
    if (datalen == 16 && data[12] == 0x0 && data[13] == 0x68 && data[14] == 0x34 && data[15] == 0x0) {
        return 0;
    }
    int payloadsize = datalen - 12;
#ifdef DUMP_AUDIO
    // Undecrypted file
    if (file_source != NULL) {
        fwrite(&data[12], payloadsize, 1, file_source);
    }
#endif
    
    logger_log(raop_buffer->logger, LOGGER_DEBUG, "seqnum = %d payloadsize = %d", seqnum, payloadsize);

    // We only process samples we received in order
    // If this design leads to a noticeable amount of artifacts, reintroduce a buffer system
    if (!raop_buffer->first_packet && seqnum_cmp(seqnum, raop_buffer->last_seqnum) <= 0) {
        logger_log(raop_buffer->logger, LOGGER_DEBUG, "seqnum = %d last_seqnum = %d cmp = %hd", seqnum, raop_buffer->last_seqnum, seqnum_cmp(seqnum, raop_buffer->last_seqnum));
    	return 0;
    }

    encryptedlen = payloadsize/16*16;
    memset(output, 0, payloadsize);
    // Need to be initialized internally
    aes_ctx_t *aes_ctx_audio = aes_cbc_init(raop_buffer->aeskey, raop_buffer->aesiv, AES_DECRYPT);
    aes_cbc_decrypt(aes_ctx_audio, &data[12], output, encryptedlen);
    aes_cbc_destroy(aes_ctx_audio);

    memcpy(output+encryptedlen, &data[12+encryptedlen], payloadsize-encryptedlen);
    *outputlen = payloadsize;

#ifdef DUMP_AUDIO
    // Decrypted file
    if (file_aac != NULL) {
        fwrite(output, payloadsize, 1, file_aac);
    }
#endif

    raop_buffer->last_seqnum = seqnum;
    raop_buffer->first_packet = false;

    return 1;
}
