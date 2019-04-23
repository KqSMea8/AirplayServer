//
// Created by Florian Draschbacher on 2019/04/23
//

/* 
 * Helper methods for various crypto operations.
 * Uses OpenSSL behind the scenes.
*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 128bit AES in CTR mode

#define AES_128_BLOCK_SIZE 16

typedef enum aes_direction_e { AES_DECRYPT, AES_ENCRYPT } aes_direction_t;

typedef struct aes_ctx_s aes_ctx_t;

aes_ctx_t *aes_ctr_init(const uint8_t *key, const uint8_t *iv);
void aes_ctr_reset(aes_ctx_t *ctx);
void aes_ctr_encrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len);
void aes_ctr_decrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len);
void aes_ctr_start_fresh_block(aes_ctx_t *ctx);
void aes_ctr_destroy(aes_ctx_t *ctx);

aes_ctx_t *aes_cbc_init(const uint8_t *key, const uint8_t *iv, aes_direction_t direction);
void aes_cbc_reset(aes_ctx_t *ctx);
void aes_cbc_encrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len);
void aes_cbc_decrypt(aes_ctx_t *ctx, const uint8_t *in, uint8_t *out, int len);
void aes_cbc_destroy(aes_ctx_t *ctx);

// SHA512

typedef struct sha_ctx_s sha_ctx_t;
sha_ctx_t *sha_init();
void sha_update(sha_ctx_t *ctx, const uint8_t *in, int len);
void sha_final(sha_ctx_t *ctx, uint8_t *out, unsigned int *len);
void sha_reset(sha_ctx_t *ctx);
void sha_destroy(sha_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
#endif
