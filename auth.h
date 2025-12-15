#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>
#include <time.h>

#define CLIPBOARD_TIMEOUT_SECONDS 300

#define MAX_LOGIN_ATTEMPTS 5
#define IDLE_TIMEOUT_SECONDS 300
#define AUTH_STATUS_FILE "auth_status.dat"
#define VERIFIER_FILE "verifier.dat"


bool init_master_password(const char *password);
bool verify_master_password(const char *password);
int get_encryption_key(const char *password, unsigned char *key_out);





#endif
