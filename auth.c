//Filename : auth.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/crypto.h>  // For CRYPTO_memcmp
#include <openssl/err.h>
#include "auth.h"
#include "Encryption.h"
#include "logging.h"

static const char *VERIFIER_TEXT = "PasswordManagerVerifier";
static unsigned char salt[SALT_LENGTH];

bool init_master_password(const char *password) {
    if (!password) return false;

    if (!generate_salt(salt)) {
        log_message_error("Failed to generate salt");
        return false;
    }

    unsigned char key[KEY_LENGTH];
    if (!derive_key_pbkdf2(password, salt, key)) {
        log_message_error("Failed to derive key");
        return false;
    }

    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char nonce[NONCE_LENGTH];
    unsigned char tag[TAG_LENGTH];

    if (!aes_gcm_encrypt((const unsigned char *)VERIFIER_TEXT, strlen(VERIFIER_TEXT),
                         key, &ciphertext, &ciphertext_len,
                         nonce, tag)) {
        log_message_error("Failed to encrypt verifier");
        OPENSSL_cleanse(key, KEY_LENGTH);
        return false;
    }

    FILE *f = fopen(VERIFIER_FILE, "wb");
    if (!f) {
        log_message_error("Failed to open verifier file");
        OPENSSL_cleanse(ciphertext, ciphertext_len);
        OPENSSL_cleanse(key, KEY_LENGTH);
        free(ciphertext);
        return false;
    }

    fwrite(salt, 1, SALT_LENGTH, f);
    fwrite(nonce, 1, NONCE_LENGTH, f);
    fwrite(tag, 1, TAG_LENGTH, f);
    fwrite(ciphertext, 1, ciphertext_len, f);
    fclose(f);
    OPENSSL_cleanse(ciphertext, ciphertext_len);
    free(ciphertext);
    OPENSSL_cleanse(key, KEY_LENGTH);
    return true;
}

bool verify_master_password(const char *password) {
    if (!password) return false;

    FILE *f = fopen(VERIFIER_FILE, "rb");
    if (!f) return false;

    unsigned char file_salt[SALT_LENGTH];
    unsigned char nonce[NONCE_LENGTH];
    unsigned char tag[TAG_LENGTH];

    fread(file_salt, 1, SALT_LENGTH, f);
    fread(nonce, 1, NONCE_LENGTH, f);
    fread(tag, 1, TAG_LENGTH, f);

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    long ciphertext_len = file_size - SALT_LENGTH - NONCE_LENGTH - TAG_LENGTH;
    if (ciphertext_len <= 0) {
        fclose(f);
        return false;
    }
    fseek(f, SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH, SEEK_SET);

    unsigned char *ciphertext = malloc((size_t)ciphertext_len);
    if (!ciphertext) {
        fclose(f);
        return false;
    }
    fread(ciphertext, 1, (size_t)ciphertext_len, f);
    fclose(f);

    unsigned char key[KEY_LENGTH];
    if (!derive_key_pbkdf2(password, file_salt, key)) {
        free(ciphertext);
        return false;
    }

    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    int success = aes_gcm_decrypt(ciphertext, (size_t)ciphertext_len,
                                 key, nonce, tag,
                                 &plaintext, &plaintext_len);
    free(ciphertext);
    OPENSSL_cleanse(key, KEY_LENGTH);

    if (!success || !plaintext) {
        if (plaintext) {
            free(plaintext);
        }
        return false;
    }

    int result = (plaintext_len == strlen(VERIFIER_TEXT) &&
                 CRYPTO_memcmp(plaintext, VERIFIER_TEXT, plaintext_len) == 0);

    OPENSSL_cleanse(plaintext, plaintext_len);
    free(plaintext);

    memcpy(salt, file_salt, SALT_LENGTH);

    return result;
}

int get_encryption_key(const char *password, unsigned char *key_out) {
    if (!password || !key_out) return 0;
    return derive_key_pbkdf2(password, salt, key_out);
}

