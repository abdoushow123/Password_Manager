//Filename : Encryption.c
#include "Encryption.h"
#include "logging.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


int derive_key_pbkdf2(const char *password, const unsigned char *salt, unsigned char *key_out) {
    if (!password || !salt || !key_out) {
        log_message_error("PBKDF2: Invalid input");
        return 0;
    }

    const int iterations = 310000;
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_LENGTH,
                          iterations,
                          EVP_sha256(),
                          KEY_LENGTH, key_out) != 1) {
        log_message_error("PBKDF2: Derivation failed");
        return 0;
    }

    return 1;
}


int generate_salt(unsigned char *salt_out) {
    if (!salt_out) {
        log_message_error("generate_salt: NULL output buffer");
        return 0;
    }
    if (RAND_bytes(salt_out, SALT_LENGTH) != 1) {
        log_message_error("generate_salt: Failed to generate salt");
        return 0;
    }
    return 1;
}

int aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char **ciphertext, size_t *ciphertext_len,
                    unsigned char *nonce_out, unsigned char *tag_out) {

    if (!plaintext || !key || !ciphertext || !ciphertext_len || !nonce_out || !tag_out) {
        log_message_error("GCM Encrypt: Invalid input");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_message_error("GCM Encrypt: Failed to allocate context");
        return 0;
    }

    if (RAND_bytes(nonce_out, NONCE_LENGTH) != 1) {
        log_message_error("GCM Encrypt: Failed to generate nonce");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    *ciphertext = malloc(plaintext_len);
    if (!*ciphertext) {
        log_message_error("GCM Encrypt: Memory allocation failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len = 0, total_len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LENGTH, NULL) ||
        !EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_out)) {
        log_message_error("GCM Encrypt: Initialization failed");
        goto cleanup_fail;
    }

    if (!EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        log_message_error("GCM Encrypt: Encryption update failed");
        goto cleanup_fail;
    }
    total_len = len;

    if (!EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        log_message_error("GCM Encrypt: Final encryption block failed");
        goto cleanup_fail;
    }
    total_len += len;
    *ciphertext_len = total_len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag_out)) {
        log_message_error("GCM Encrypt: Failed to get tag");
        goto cleanup_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;

cleanup_fail:
    EVP_CIPHER_CTX_free(ctx);
    free(*ciphertext);
    *ciphertext = NULL;
    *ciphertext_len = 0;
    return 0;
}

int aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    const unsigned char *nonce, const unsigned char *tag,
                    unsigned char **plaintext_out, size_t *plaintext_len_out) {

    if (!ciphertext || ciphertext_len == 0 ||
        !key || !nonce || !tag ||
        !plaintext_out || !plaintext_len_out) {
        log_message_error("GCM Decrypt: Invalid input");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_message_error("GCM Decrypt: Failed to create context");
        return 0;
    }

    *plaintext_out = malloc(ciphertext_len);  // ciphertext_len is the upper bound
    if (!*plaintext_out) {
        log_message_error("GCM Decrypt: Memory allocation failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len = 0, total_len = 0;
    int success = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LENGTH, NULL) ||
        !EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        log_message_error("GCM Decrypt: Initialization failed");
        goto cleanup_fail;
    }

    if (!EVP_DecryptUpdate(ctx, *plaintext_out, &len, ciphertext, ciphertext_len)) {
        log_message_error("GCM Decrypt: Update failed");
        goto cleanup_fail;
    }

    total_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, (void *)tag)) {
        log_message_error("GCM Decrypt: Failed to set tag");
        goto cleanup_fail;
    }

    if (EVP_DecryptFinal_ex(ctx, *plaintext_out + len, &len) <= 0) {
        log_message_error("GCM Decrypt: Tag verification failed");
        goto cleanup_fail;
    }

    total_len += len;
    *plaintext_len_out = total_len;
    success = 1;

cleanup_fail:
    if (!success && *plaintext_out) {
        OPENSSL_cleanse(*plaintext_out, ciphertext_len);
        free(*plaintext_out);
        *plaintext_out = NULL;
        *plaintext_len_out = 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}


