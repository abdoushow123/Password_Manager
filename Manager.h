#ifndef MANAGER_H
#define MANAGER_H

#include <stdbool.h>
#include <gtk/gtk.h>

#define SERVICE_MAX 50
#define USERNAME_MAX 50
#define MAIL_MAX 100
#define PASSWORD_MAX 50

typedef struct {
    char Service[SERVICE_MAX];
    char Username[USERNAME_MAX];
    char Mail[MAIL_MAX];
    char Password[PASSWORD_MAX];
} Password_Storing;


typedef struct cell {
    Password_Storing P;
    struct cell *next;
} *liste;

typedef struct {
    Password_Storing entry;
    liste *list_head;
    const unsigned char *key;
    GtkWidget *parent_window;
} ModifyData;


liste create_entry(Password_Storing data);
void add_entry(liste *l, Password_Storing data);
void save_entries_to_file(liste l, const unsigned char *key);
void load_entries_from_file(liste *l, const unsigned char *key);
void display_entries(liste l);
int delete_entry(liste *l, const char *service, const char *username);
char *generate_random_password(int len);
int modify_entry(liste l, const char *service, const char *username, Password_Storing new_data);
liste search_entries(liste l, const char *search_term);
void free_list(liste l);
bool sanitize_string(const char *input, char *output, size_t max_len);

#endif

