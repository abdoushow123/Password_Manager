//Filename : Manager.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <time.h>
#include "Manager.h"
#include "Encryption.h"
#include "logging.h"
#include <stdint.h>
#include <errno.h>

#define ENTRY_FILE "entries.dat"
#define HMAC_KEY_LEN 32
#define HMAC_DIGEST_LEN 32

bool sanitize_string(const char *input, char *output, size_t max_len) {
    if (!input || !output || max_len == 0) return false;
    size_t i = 0;
    for (; i < max_len - 1 && input[i]; i++) {
        if (iscntrl((unsigned char)input[i])) {
            return false;
        }
        output[i] = input[i];
    }
    output[i] = '\0';
    return true;
}


liste create_entry(Password_Storing data) {
    liste new_node = (liste)malloc(sizeof(struct cell));
    if (!new_node) {
        log_message_error("Memory allocation failed in create_entry");
        return NULL;
    }
    new_node->P = data;
    new_node->next = NULL;
    return new_node;
}

void add_entry(liste *l, Password_Storing data) {
    liste new_node = create_entry(data);
    if (!new_node) return;

    if (*l == NULL) {
        *l = new_node;
    } else {
        liste temp = *l;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = new_node;
    }
}



void save_entries_to_file(liste l, const unsigned char *key) {
    if (!key) {
        log_message_error("save_entries_to_file called with NULL key");
        return;
    }

    FILE *f = fopen(ENTRY_FILE ".tmp", "wb");
    if (!f) {
        log_message_error("Failed to open temporary entries file for writing.");
        return;
    }

    size_t buffer_size = 0;
    size_t buffer_capacity = 8192;
    char *buffer = malloc(buffer_capacity);
    if (!buffer) {
        log_message_error("Memory allocation failed in save_entries_to_file");
        fclose(f);
        return;
    }
    buffer[0] = '\0';

    for (liste current = l; current != NULL; current = current->next) {
        char line[512];
        snprintf(line, sizeof(line), "%s|%s|%s|%s\n",
                 current->P.Service,
                 current->P.Username,
                 current->P.Mail,
                 current->P.Password);

        size_t line_len = strlen(line);
        if (buffer_size + line_len + 1 > buffer_capacity) {
            buffer_capacity *= 2;
            char *tmp = realloc(buffer, buffer_capacity);
            if (!tmp) {
                log_message_error("Memory reallocation failed");
                free(buffer);
                fclose(f);
                return;
            }
            buffer = tmp;
        }
        strcat(buffer, line);
        buffer_size += line_len;
    }

    unsigned char nonce[NONCE_LENGTH];
    unsigned char tag[TAG_LENGTH];
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;

    if (!aes_gcm_encrypt((unsigned char *)buffer, strlen(buffer),
                         key, &ciphertext, &ciphertext_len,
                         nonce, tag)) {
        log_message_error("Encryption failed");
        free(buffer);
        fclose(f);
        return;
    }
    OPENSSL_cleanse(buffer, buffer_size);
    free(buffer);


    size_t mac_input_len = NONCE_LENGTH + TAG_LENGTH + ciphertext_len;
    unsigned char *mac_input = malloc(mac_input_len);
    if (!mac_input) {
        log_message_error("MAC buffer allocation failed");
        OPENSSL_cleanse(ciphertext, ciphertext_len);
        free(ciphertext);
        fclose(f);
        return;
    }
    memcpy(mac_input, nonce, NONCE_LENGTH);
    memcpy(mac_input + NONCE_LENGTH, tag, TAG_LENGTH);
    memcpy(mac_input + NONCE_LENGTH + TAG_LENGTH, ciphertext, ciphertext_len);

    unsigned char hmac[HMAC_DIGEST_LEN];
    HMAC(EVP_sha256(), key, HMAC_KEY_LEN, mac_input, mac_input_len, hmac, NULL);
    free(mac_input);


    fwrite(nonce, 1, NONCE_LENGTH, f);
    fwrite(tag, 1, TAG_LENGTH, f);
    fwrite(ciphertext, 1, ciphertext_len, f);
    fwrite(hmac, 1, HMAC_DIGEST_LEN, f);

    OPENSSL_cleanse(ciphertext, ciphertext_len);
    free(ciphertext);
    fclose(f);

    FILE *verify = fopen(ENTRY_FILE ".tmp", "rb");
    if (!verify) {
        log_message_error("Failed to reopen temp file for verification");
        return;
    }
    fseek(verify, 0, SEEK_END);
    long size = ftell(verify);
    fclose(verify);

    if (size < (NONCE_LENGTH + TAG_LENGTH + 1)) {
        log_message_error("Written file is too small, removing temp file.");
        unlink(ENTRY_FILE ".tmp");
        return;
    }

    remove(ENTRY_FILE);
    if (rename(ENTRY_FILE ".tmp", ENTRY_FILE) != 0) {
        log_message_error("rename() failed: %s", strerror(errno));
        unlink(ENTRY_FILE ".tmp");
    }
    OPENSSL_cleanse(nonce, NONCE_LENGTH);
    OPENSSL_cleanse(tag, TAG_LENGTH);
    OPENSSL_cleanse(ciphertext, ciphertext_len);

}


void load_entries_from_file(liste *l, const unsigned char *key) {
    if (!key) {
        log_message_error("load_entries_from_file called with NULL key");
        return;
    }

    FILE *f = fopen(ENTRY_FILE, "rb");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    long min_size = NONCE_LENGTH + TAG_LENGTH + HMAC_DIGEST_LEN + 1;
    if (file_size < min_size) {
        log_message_error("File too small or corrupted");
        fclose(f);
        return;
    }

    unsigned char nonce[NONCE_LENGTH], tag[TAG_LENGTH], hmac_read[HMAC_DIGEST_LEN];

    fread(nonce, 1, NONCE_LENGTH, f);
    fread(tag, 1, TAG_LENGTH, f);

    long ciphertext_len = file_size - NONCE_LENGTH - TAG_LENGTH - HMAC_DIGEST_LEN;


    long expected_size = NONCE_LENGTH + TAG_LENGTH + ciphertext_len + HMAC_DIGEST_LEN;
    if (file_size != expected_size) {
        log_message_error("Unexpected file size � possible tampering detected");
        fclose(f);
        return;
    }

    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fclose(f);
        log_message_error("Memory allocation failed");
        return;
    }

    fread(ciphertext, 1, ciphertext_len, f);
    fread(hmac_read, 1, HMAC_DIGEST_LEN, f);
    fclose(f);


    size_t mac_input_len = NONCE_LENGTH + TAG_LENGTH + ciphertext_len;
    unsigned char *mac_input = malloc(mac_input_len);
    if (!mac_input) {
        free(ciphertext);
        log_message_error("MAC input allocation failed");
        return;
    }

    memcpy(mac_input, nonce, NONCE_LENGTH);
    memcpy(mac_input + NONCE_LENGTH, tag, TAG_LENGTH);
    memcpy(mac_input + NONCE_LENGTH + TAG_LENGTH, ciphertext, ciphertext_len);

    unsigned char hmac_calc[HMAC_DIGEST_LEN];
    HMAC(EVP_sha256(), key, HMAC_KEY_LEN, mac_input, mac_input_len, hmac_calc, NULL);
    free(mac_input);

    if (CRYPTO_memcmp(hmac_read, hmac_calc, HMAC_DIGEST_LEN) != 0) {
        free(ciphertext);
        log_message_error("HMAC verification failed � file integrity compromised");
        return;
    }

    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;

    if (!aes_gcm_decrypt(ciphertext, ciphertext_len, key, nonce, tag, &plaintext, &plaintext_len)) {
        log_message_error("Decryption failed after HMAC verification");
        OPENSSL_cleanse(ciphertext, ciphertext_len);
        free(ciphertext);
        return;
    }
    OPENSSL_cleanse(ciphertext, ciphertext_len);
    free(ciphertext);

    // Parse entries as before
    char *line = strtok((char *)plaintext, "\n");
    while (line != NULL) {
        Password_Storing data;
        if (sscanf(line, "%49[^|]|%49[^|]|%99[^|]|%49[^\n]",
                   data.Service, data.Username, data.Mail, data.Password) == 4) {
            add_entry(l, data);
        }
        line = strtok(NULL, "\n");
    }

    OPENSSL_cleanse(nonce, NONCE_LENGTH);
    OPENSSL_cleanse(tag, TAG_LENGTH);
    OPENSSL_cleanse(ciphertext, ciphertext_len);

}




void display_entries(liste l) {
    if (l == NULL) {
        log_message_info("No entries stored.");
        return;
    }
    log_message("--- Stored Entries ---");
    while (l != NULL) {
        log_message("Service: %s", l->P.Service);
        log_message("Username: %s", l->P.Username);
        log_message("Email: %s", l->P.Mail);
        log_message("Password: %s", l->P.Password);
        log_message("------------------------");
        l = l->next;
    }
}

int delete_entry(liste *l, const char *service, const char *username) {
    if (!service || !username) return 0;

    liste current = *l;
    liste prev = NULL;

    while (current != NULL) {
        if (strcmp(current->P.Service, service) == 0 && strcmp(current->P.Username, username) == 0) {
            if (prev == NULL) {
                *l = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            return 1;
        }
        prev = current;
        current = current->next;
    }
    return 0;
}

char *generate_random_password(int len) {
    const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{};:,.<>?";
    int charset_size = sizeof(charset) - 1;

    char *password = malloc(len + 1);
    if (!password)
        return NULL;

    unsigned char rand_bytes[len];

    if (RAND_bytes(rand_bytes, len) != 1) {
        log_message_error("RAND_bytes failed in generate_random_password");
        return NULL;
    }

    for (int i = 0; i < len; i++) {
        password[i] = charset[rand_bytes[i] % charset_size];
    }
    password[len] = '\0';
    return password;
}

int modify_entry(liste l, const char *service, const char *username, Password_Storing new_data) {
    if (!service || !username) return 0;

    liste current = l;
    while (current != NULL) {
        if (strcmp(current->P.Service, service) == 0 && strcmp(current->P.Username, username) == 0) {
            if (!sanitize_string(new_data.Service, current->P.Service, SERVICE_MAX) ||
                !sanitize_string(new_data.Username, current->P.Username, USERNAME_MAX) ||
                !sanitize_string(new_data.Mail, current->P.Mail, MAIL_MAX) ||
                !sanitize_string(new_data.Password, current->P.Password, PASSWORD_MAX)) {
                log_message_error("Invalid characters in modify_entry input");
                return 0;
            }
            return 1;
        }
        current = current->next;
    }
    return 0;
}


liste search_entries(liste l, const char *search_term) {
    if (!search_term || strlen(search_term) == 0) {
        return l;
    }

    liste results = NULL;
    liste current = l;

    while (current != NULL) {
        if (strstr(current->P.Service, search_term) != NULL ||
            strstr(current->P.Username, search_term) != NULL ||
            strstr(current->P.Mail, search_term) != NULL) {
            add_entry(&results, current->P);
        }
        current = current->next;
    }

    return results;
}

void free_list(liste l) {
    liste temp;
    while (l != NULL) {
        temp = l;
        l = l->next;
        free(temp);
    }
}

