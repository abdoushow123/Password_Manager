#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>

#define SHA256_DIGEST_LENGTH 32

#define KEY_LENGTH 32      // 256-bit AES key
#define SALT_LENGTH 16     // 128-bit salt
#define NONCE_LENGTH 12    // 96-bit nonce for AES-GCM
#define TAG_LENGTH 16      // 128-bit tag for AES-GCM

int derive_key_pbkdf2(const char *password, const unsigned char *salt, unsigned char *key_out);
int generate_salt(unsigned char *salt_out);

int aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char **ciphertext, size_t *ciphertext_len,
                    unsigned char *nonce_out, unsigned char *tag_out);

int aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    const unsigned char *nonce,
                    const unsigned char *tag,
                    unsigned char **plaintext, size_t *plaintext_len);

#endif








