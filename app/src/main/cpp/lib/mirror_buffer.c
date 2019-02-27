//
// Created by Administrator on 2019/1/29/029.
//

#include "mirror_buffer.h"
#include "raop_rtp.h"
#include "raop_rtp.h"
#include <stdint.h>
#include "crypto/crypto.h"
#include "aes.h"
#include "compat.h"
#include "ed25519/sha512.h"
#include <math.h>
#include <malloc.h>
#include <assert.h>
//#define DUMP_KEI_IV
struct mirror_buffer_s {
    logger_t *logger;
    struct AES_ctx aes_ctx;
    int nextDecryptCount;
    uint8_t og[16];
    /* AES key and IV */
    // 需要二次加工才能使用
    unsigned char aeskey[RAOP_AESKEY_LEN];
    unsigned char ecdh_secret[32];
};

void
mirror_buffer_init_aes(mirror_buffer_t *mirror_buffer, uint64_t streamConnectionID)
{
    sha512_context ctx;
    unsigned char eaeskey[64] = {};
    memcpy(eaeskey, mirror_buffer->aeskey, 16);
    sha512_init(&ctx);
    sha512_update(&ctx, eaeskey, 16);
    sha512_update(&ctx, mirror_buffer->ecdh_secret, 32);
    sha512_final(&ctx, eaeskey);

    unsigned char hash1[64];
    unsigned char hash2[64];
    char* skey = "AirPlayStreamKey";
    char* siv = "AirPlayStreamIV";
    unsigned char skeyall[255];
    unsigned char sivall[255];
    sprintf(skeyall, "%s%llu", skey, streamConnectionID);
    sprintf(sivall, "%s%llu", siv, streamConnectionID);
    sha512_init(&ctx);
    sha512_update(&ctx, skeyall, strlen(skeyall));
    sha512_update(&ctx, eaeskey, 16);
    sha512_final(&ctx, hash1);

    sha512_init(&ctx);
    sha512_update(&ctx, sivall, strlen(sivall));
    sha512_update(&ctx, eaeskey, 16);
    sha512_final(&ctx, hash2);

    unsigned char decrypt_aeskey[16];
    unsigned char decrypt_aesiv[16];
    memcpy(decrypt_aeskey, hash1, 16);
    memcpy(decrypt_aesiv, hash2, 16);
#ifdef DUMP_KEI_IV
    FILE* keyfile = fopen("/sdcard/111.keyiv", "wb");
    fwrite(decrypt_aeskey, 16, 1, keyfile);
    fwrite(decrypt_aesiv, 16, 1, keyfile);
    fclose(keyfile);
#endif
    // 需要在外部初始化
    AES_init_ctx_iv(&mirror_buffer->aes_ctx, decrypt_aeskey, decrypt_aesiv);
    mirror_buffer->nextDecryptCount = 0;
}

mirror_buffer_t *
mirror_buffer_init(logger_t *logger,
        const unsigned char *aeskey,
        const unsigned char *ecdh_secret)
{
    mirror_buffer_t *mirror_buffer;
    assert(aeskey);
    assert(ecdh_secret);
    mirror_buffer = calloc(1, sizeof(mirror_buffer_t));
    if (!mirror_buffer) {
        return NULL;
    }
    memcpy(mirror_buffer->aeskey, aeskey, RAOP_AESKEY_LEN);
    memcpy(mirror_buffer->ecdh_secret, ecdh_secret, 32);
    mirror_buffer->logger = logger;
    mirror_buffer->nextDecryptCount = 0;
    //mirror_buffer_init_aes(mirror_buffer, aeskey, ecdh_secret, streamConnectionID);
    return mirror_buffer;
}

void mirror_buffer_decrypt(mirror_buffer_t *mirror_buffer, unsigned char* input, unsigned char* output, int inputLen) {
    // 开始解密
    if (mirror_buffer->nextDecryptCount > 0) {//mirror_buffer->nextDecryptCount = 10
        for (int i = 0; i < mirror_buffer->nextDecryptCount; i++) {
            output[i] = (input[i] ^ mirror_buffer->og[(16 - mirror_buffer->nextDecryptCount) + i]);
        }
    }
    // 处理加密的字节
    int encryptlen = ((inputLen - mirror_buffer->nextDecryptCount) / 16) * 16;
    // aes解密
    AES_CTR_xcrypt_buffer(&mirror_buffer->aes_ctx, input + mirror_buffer->nextDecryptCount, encryptlen);
    // 复制到输出
    memcpy(output + mirror_buffer->nextDecryptCount, input + mirror_buffer->nextDecryptCount, encryptlen);
    int outputlength = mirror_buffer->nextDecryptCount + encryptlen;
    //处理剩余长度
    int restlen = (inputLen - mirror_buffer->nextDecryptCount) % 16;
    int reststart = inputLen - restlen;
    mirror_buffer->nextDecryptCount = 0;
    if (restlen > 0) {
        memset(mirror_buffer->og, 0, 16);
        memcpy(mirror_buffer->og, input + reststart, restlen);
        AES_CTR_xcrypt_buffer(&mirror_buffer->aes_ctx, mirror_buffer->og, 16);
        for (int j = 0; j < restlen; j++) {
            output[reststart + j] = mirror_buffer->og[j];
        }
        outputlength += restlen;
        mirror_buffer->nextDecryptCount = 16 - restlen;// 差16-6=10个字节
    }
}

void
mirror_buffer_destroy(mirror_buffer_t *mirror_buffer)
{
    if (mirror_buffer) {
        free(mirror_buffer);
    }
}
