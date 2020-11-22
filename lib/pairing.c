/**
 *  Copyright (C) 2018  Juho Vähä-Herttua
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

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "pairing.h"
#include "crypto.h"

#define SALT_KEY "Pair-Verify-AES-Key"
#define SALT_IV "Pair-Verify-AES-IV"

struct pairing_s {
    EVP_PKEY *ed;
};

typedef enum {
    STATUS_INITIAL,
    STATUS_SETUP,
    STATUS_HANDSHAKE,
    STATUS_FINISHED
} status_t;

struct pairing_session_s {
    status_t status;

    EVP_PKEY_CTX *pkey_ctx;
    EVP_MD_CTX *md_ctx;

    EVP_PKEY *ed_ours;
    EVP_PKEY *ed_theirs;

    EVP_PKEY *ecdh_ours;
    EVP_PKEY *ecdh_theirs;
    unsigned char ecdh_secret[X25519_KEY_SIZE];
};

static int
derive_key_internal(pairing_session_t *session, const unsigned char *salt, unsigned int saltlen, unsigned char *key, unsigned int keylen)
{
    unsigned char hash[SHA512_DIGEST_LENGTH];

    if (keylen > sizeof(hash)) {
        return -1;
    }

    sha_ctx_t *ctx = sha_init();
    sha_update(ctx, salt, saltlen);
    sha_update(ctx, session->ecdh_secret, X25519_KEY_SIZE);
    sha_final(ctx, hash, NULL);
    sha_destroy(ctx);

    memcpy(key, hash, keylen);
    return 0;
}

pairing_t *
pairing_init_generate()
{
    pairing_t *pairing;
    EVP_PKEY_CTX *pctx;

    pairing = calloc(1, sizeof(pairing_t));
    if (!pairing) {
        return NULL;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) {
        crypto_handle_error(__func__);
    }

    if (!EVP_PKEY_keygen_init(pctx)) {
        crypto_handle_error(__func__);
    }
    if (!EVP_PKEY_keygen(pctx, &pairing->ed)) {
        crypto_handle_error(__func__);
    }

    EVP_PKEY_CTX_free(pctx);

    return pairing;
}

int
pairing_get_public_key(pairing_t *pairing, unsigned char public_key[X25519_KEY_SIZE])
{
    assert(pairing);

    if (!EVP_PKEY_get_raw_public_key(pairing->ed, public_key, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }

    return 0;
}

void
pairing_get_ecdh_secret_key(pairing_session_t *session, unsigned char ecdh_secret[X25519_KEY_SIZE])
{
    assert(session);
    memcpy(ecdh_secret, session->ecdh_secret, X25519_KEY_SIZE);
}


pairing_session_t *
pairing_session_init(pairing_t *pairing)
{
    pairing_session_t *session;

    if (!pairing) {
        return NULL;
    }

    session = calloc(1, sizeof(pairing_session_t));
    if (!session) {
        return NULL;
    }

    session->pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!session->pkey_ctx) {
        crypto_handle_error(__func__);
    }
    if (!EVP_PKEY_keygen_init(session->pkey_ctx)) {
        crypto_handle_error(__func__);
    }

    session->md_ctx = EVP_MD_CTX_new();
    if (!session->md_ctx) {
        crypto_handle_error(__func__);
    }

    session->ed_ours = pairing->ed;
    if (!EVP_PKEY_up_ref(pairing->ed)) {
        crypto_handle_error(__func__);
    }

    session->status = STATUS_INITIAL;

    return session;
}

void
pairing_session_set_setup_status(pairing_session_t *session)
{
    assert(session);
    session->status = STATUS_SETUP;
}

int
pairing_session_check_handshake_status(pairing_session_t *session)
{
    assert(session);
    if (session->status != STATUS_SETUP) {
        return -1;
    }
    return 0;
}

int
pairing_session_handshake(pairing_session_t *session, const unsigned char ecdh_key[X25519_KEY_SIZE],
                          const unsigned char ed_key[X25519_KEY_SIZE])
{
    EVP_PKEY_CTX *shared_ctx;

    assert(session);

    if (session->status == STATUS_FINISHED) {
        return -1;
    }

    session->ecdh_theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ecdh_key, X25519_KEY_SIZE);
    if (!session->ecdh_theirs) {
        crypto_handle_error(__func__);
    }

    session->ed_theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed_key, X25519_KEY_SIZE);
    if (!session->ed_theirs) {
        crypto_handle_error(__func__);
    }

    if (!EVP_PKEY_keygen(session->pkey_ctx, &session->ecdh_ours)) {
        crypto_handle_error(__func__);
    }

    shared_ctx = EVP_PKEY_CTX_new(session->ecdh_ours, NULL);
    if (!shared_ctx) {
        return -2;
    }
    if (!EVP_PKEY_derive_init(shared_ctx)) {
        crypto_handle_error(__func__);
    }
    if (!EVP_PKEY_derive_set_peer(shared_ctx, session->ecdh_theirs)) {
        crypto_handle_error(__func__);
    }
    if (!EVP_PKEY_derive(shared_ctx, session->ecdh_secret, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }
    EVP_PKEY_CTX_free(shared_ctx);

    session->status = STATUS_HANDSHAKE;
    return 0;
}

int
pairing_session_get_public_key(pairing_session_t *session, unsigned char ecdh_key[X25519_KEY_SIZE])
{
    assert(session);

    if (session->status != STATUS_HANDSHAKE) {
        return -1;
    }

    if (!EVP_PKEY_get_raw_public_key(session->ecdh_ours, ecdh_key, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }

    return 0;
}

int
pairing_session_get_signature(pairing_session_t *session, unsigned char signature[PAIRING_SIG_SIZE])
{
    unsigned char sig_msg[PAIRING_SIG_SIZE];
    unsigned char key[AES_128_BLOCK_SIZE];
    unsigned char iv[AES_128_BLOCK_SIZE];
    aes_ctx_t *aes_ctx;

    assert(session);

    if (session->status != STATUS_HANDSHAKE) {
        return -1;
    }

    /* First sign the public ECDH keys of both parties */
    if (!EVP_PKEY_get_raw_public_key(session->ecdh_ours, sig_msg, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }
    if (!EVP_PKEY_get_raw_public_key(session->ecdh_theirs, sig_msg + X25519_KEY_SIZE, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }

    if (!EVP_DigestSignInit(session->md_ctx, NULL, NULL, NULL, session->ed_ours)) {
        crypto_handle_error(__func__);
    }
    if (!EVP_DigestSign(session->md_ctx, signature, &(size_t) {PAIRING_SIG_SIZE}, sig_msg, PAIRING_SIG_SIZE)) {
        crypto_handle_error(__func__);
    }

    /* Then encrypt the result with keys derived from the shared secret */
    derive_key_internal(session, (const unsigned char *) SALT_KEY, strlen(SALT_KEY), key, sizeof(key));
    derive_key_internal(session, (const unsigned char *) SALT_IV, strlen(SALT_IV), iv, sizeof(iv));

    aes_ctx = aes_ctr_init(key, iv);
    aes_ctr_encrypt(aes_ctx, signature, signature, PAIRING_SIG_SIZE);
    aes_ctr_destroy(aes_ctx);

    return 0;
}

int
pairing_session_finish(pairing_session_t *session, const unsigned char signature[PAIRING_SIG_SIZE])
{
    unsigned char sig_buffer[PAIRING_SIG_SIZE];
    unsigned char sig_msg[PAIRING_SIG_SIZE];
    unsigned char key[AES_128_BLOCK_SIZE];
    unsigned char iv[AES_128_BLOCK_SIZE];
    aes_ctx_t *aes_ctx;

    assert(session);

    if (session->status != STATUS_HANDSHAKE) {
        return -1;
    }

    /* First decrypt the signature with keys derived from the shared secret */
    derive_key_internal(session, (const unsigned char *) SALT_KEY, strlen(SALT_KEY), key, sizeof(key));
    derive_key_internal(session, (const unsigned char *) SALT_IV, strlen(SALT_IV), iv, sizeof(iv));

    aes_ctx = aes_ctr_init(key, iv);
    /* One fake round for the initial handshake encryption */
    aes_ctr_encrypt(aes_ctx, sig_buffer, sig_buffer, PAIRING_SIG_SIZE);
    aes_ctr_encrypt(aes_ctx, signature, sig_buffer, PAIRING_SIG_SIZE);
    aes_ctr_destroy(aes_ctx);

    /* Then verify the signature with public ECDH keys of both parties */
    if (!EVP_PKEY_get_raw_public_key(session->ecdh_theirs, sig_msg, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }
    if (!EVP_PKEY_get_raw_public_key(session->ecdh_ours, sig_msg + X25519_KEY_SIZE, &(size_t) {X25519_KEY_SIZE})) {
        crypto_handle_error(__func__);
    }

    if (!EVP_DigestVerifyInit(session->md_ctx, NULL, NULL, NULL, session->ed_theirs)) {
        crypto_handle_error(__func__);
    }

    int ret = EVP_DigestVerify(session->md_ctx, sig_buffer, PAIRING_SIG_SIZE, sig_msg, PAIRING_SIG_SIZE);
    if (ret == 0) {
        return -2;
    } else if (ret < 0) {
        crypto_handle_error(__func__);
    }

    session->status = STATUS_FINISHED;
    return 0;
}

void
pairing_session_destroy(pairing_session_t *session)
{
    if (session) {
        EVP_PKEY_free(session->ed_ours);
        EVP_PKEY_free(session->ed_theirs);

        EVP_PKEY_free(session->ecdh_ours);
        EVP_PKEY_free(session->ecdh_theirs);

        EVP_MD_CTX_free(session->md_ctx);
        EVP_PKEY_CTX_free(session->pkey_ctx);

        free(session);
    }
}

void
pairing_destroy(pairing_t *pairing)
{
    if (pairing) {
        EVP_PKEY_free(pairing->ed);
        free(pairing);
    }
}
