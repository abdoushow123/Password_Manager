#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include "auth.h"
#include "Manager.h"
#include "Encryption.h"
#include "logging.h"



// Function declarations
static void start_lockout_ui(void);
static void clear_entries_list(liste *l);
static void show_login_ui(void);
static void refresh_entries_list(GtkListStore *store);
static void show_main_ui(void);
static void start_idle_timer(void);
static gboolean reset_idle_timer(GtkWidget *widget, GdkEvent *event, gpointer user_data);
static gboolean idle_timeout_callback(gpointer user_data);
static void build_main_ui(GtkWidget *container);


static unsigned char master_key[KEY_LENGTH];
static liste entries = NULL;
static guint idle_timer_id = 0;
static int failed_login_attempts = 0;
static guint lockout_timer_id = 0;
static gint64 lockout_end_time = 0;
#define LOCKOUT_DURATION 300 // 5 minutes in seconds


static GtkWidget *window;
static GtkWidget *stack;

static GtkWidget *login_entry;
static GtkWidget *login_button;
static GtkWidget *lockout_label;
static GtkWidget *progress_bar;

static GtkWidget *reg_entry;
static GtkWidget *reg_confirm_entry;
static GtkWidget *reg_button;


static void clear_entries_list_and_key() {
    clear_entries_list(&entries);
    memset(master_key, 0, sizeof(master_key));
}


static gboolean idle_timeout_callback(gpointer user_data) {
    (void)user_data;
    log_message_info("Idle timeout reached. Locking application.");
    clear_entries_list_and_key();
    
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
        GTK_DIALOG_MODAL, 
        GTK_MESSAGE_INFO, 
        GTK_BUTTONS_OK,
        "Idle timeout reached. Application Locked.");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    
    show_login_ui();
    
    gtk_entry_set_text(GTK_ENTRY(login_entry), "");
    
    return G_SOURCE_REMOVE; // Stop the timer
    idle_timer_id = 0;

    return G_SOURCE_REMOVE;
}




static void show_modify_dialog(ModifyData *data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Modify Entry",
                                                    GTK_WINDOW(data->parent_window),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Save", GTK_RESPONSE_OK,
                                                    NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_container_add(GTK_CONTAINER(content), grid);

    GtkWidget *service_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(service_entry), data->entry.Service);
    GtkWidget *username_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(username_entry), data->entry.Username);
    GtkWidget *mail_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(mail_entry), data->entry.Mail);
    GtkWidget *password_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(password_entry), data->entry.Password);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Service:"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), service_entry, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Username:"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), username_entry, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Mail:"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), mail_entry, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Password:"), 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), password_entry, 1, 3, 1, 1);

    gtk_widget_show_all(dialog);

    gint result = gtk_dialog_run(GTK_DIALOG(dialog));
    if (result == GTK_RESPONSE_OK) {
        Password_Storing new_data;
        strncpy(new_data.Service, gtk_entry_get_text(GTK_ENTRY(service_entry)), SERVICE_MAX);
        strncpy(new_data.Username, gtk_entry_get_text(GTK_ENTRY(username_entry)), USERNAME_MAX);
        strncpy(new_data.Mail, gtk_entry_get_text(GTK_ENTRY(mail_entry)), MAIL_MAX);
        strncpy(new_data.Password, gtk_entry_get_text(GTK_ENTRY(password_entry)), PASSWORD_MAX);

        if (modify_entry(*(data->list_head), data->entry.Service, data->entry.Username, new_data)) {
            save_entries_to_file(*(data->list_head), data->key);
            refresh_entries_list(GTK_LIST_STORE(g_object_get_data(G_OBJECT(data->parent_window), "entries_store")));
            log_message_info("Entry modified successfully.");
        } else {
            log_message_error("Failed to modify entry.");
        }
    }

    gtk_widget_destroy(dialog);
    g_free(data);
}



static void on_modify_entry_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkTreeSelection *selection = GTK_TREE_SELECTION(user_data);
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gchar *service, *username, *mail, *password;
        gtk_tree_model_get(model, &iter, 0, &service, 1, &username, 2, &mail, 3, &password, -1);

        Password_Storing selected_entry;
        strncpy(selected_entry.Service, service, SERVICE_MAX);
        strncpy(selected_entry.Username, username, USERNAME_MAX);
        strncpy(selected_entry.Mail, mail, MAIL_MAX);
        strncpy(selected_entry.Password, password, PASSWORD_MAX);

        g_free(service);
        g_free(username);
        g_free(mail);
        g_free(password);

        ModifyData *data = g_malloc(sizeof(ModifyData));
        data->entry = selected_entry;
        data->list_head = &entries;
        data->key = master_key;
        data->parent_window = GTK_WIDGET(window);

        show_modify_dialog(data);
    }
}

static void clear_entries_list(liste *l) {
    if (l == NULL || *l == NULL) {
        return;
    }

    liste current = *l;
    while (current != NULL) {
        liste next = current->next;
        memset(&current->P, 0, sizeof(Password_Storing));
        free(current);
        current = next;
    }

    *l = NULL;
}


static void on_login_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    (void)user_data;
    
    if (failed_login_attempts >= MAX_LOGIN_ATTEMPTS) {
        start_lockout_ui();
        return;
    }
    
    const char *password = gtk_entry_get_text(GTK_ENTRY(login_entry));

    memset(master_key, 0, KEY_LENGTH);

    if (verify_master_password(password)) {
        failed_login_attempts = 0;
        gtk_widget_hide(lockout_label);
        gtk_widget_hide(progress_bar);
        
        if (get_encryption_key(password, master_key)) {
            show_main_ui();
            load_entries_from_file(&entries, master_key);
            refresh_entries_list(GTK_LIST_STORE(g_object_get_data(G_OBJECT(window), "entries_store")));
        } else {
            GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
                "Failed to initialize encryption key.");
            gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        }
    } else {
        failed_login_attempts++;
        
        if (failed_login_attempts >= MAX_LOGIN_ATTEMPTS) {
            start_lockout_ui();
        } 
        else {
            int remaining = MAX_LOGIN_ATTEMPTS - failed_login_attempts;
            char message[256];
            snprintf(message, sizeof(message), 
                    "Incorrect Master Key. %d %s remaining.", 
                    remaining, 
                    (remaining == 1) ? "attempt" : "attempts");
                    
            GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
                "%s", message);
            gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        }
    }
    
    if (password) {
        const gchar *current_text = gtk_entry_get_text(GTK_ENTRY(login_entry));
        if (current_text && *current_text) {
            // Block the signal to prevent the warning
            g_signal_handlers_block_by_func(login_entry, G_CALLBACK(gtk_entry_set_text), NULL);
            gtk_entry_set_text(GTK_ENTRY(login_entry), "");
            g_signal_handlers_unblock_by_func(login_entry, G_CALLBACK(gtk_entry_set_text), NULL);
        }
        // Clear the password from memory
        volatile char *p = (volatile char *)password;
        while (*p) {
            *p++ = '\0';
        }
    }
}



static void on_register_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    (void)user_data;
    const char *key = gtk_entry_get_text(GTK_ENTRY(reg_entry));
    const char *key_confirm = gtk_entry_get_text(GTK_ENTRY(reg_confirm_entry));

    if (strlen(key) == 0) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Master key cannot be empty.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    if (strcmp(key, key_confirm) != 0) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Master key and confirmation do not match.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    if (!init_master_password(key)) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Failed to initialize master password.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    unsigned char raw_key[KEY_LENGTH];
    if (!get_encryption_key(key, raw_key)) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Failed to derive encryption key.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    memcpy(master_key, raw_key, KEY_LENGTH);
    log_message_info("Master key set after registration.");

    load_entries_from_file(&entries, master_key);

    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "Master key registered successfully.");
    log_message_info("Master key registered successfully.");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);

    gtk_stack_set_visible_child_name(GTK_STACK(stack), "main");
}

static void build_registration_ui(GtkWidget *container) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(vbox, GTK_ALIGN_CENTER);

    gtk_container_add(GTK_CONTAINER(container), vbox);

    GtkWidget *label = gtk_label_new("Set Master Key (First Time Setup):");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    reg_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(reg_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(reg_entry), '*');
    gtk_box_pack_start(GTK_BOX(vbox), reg_entry, FALSE, FALSE, 0);

    GtkWidget *reg_confirm_label = gtk_label_new("Confirm Master Key:");
    gtk_box_pack_start(GTK_BOX(vbox), reg_confirm_label, FALSE, FALSE, 0);

    reg_confirm_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(reg_confirm_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(reg_confirm_entry), '*');
    gtk_box_pack_start(GTK_BOX(vbox), reg_confirm_entry, FALSE, FALSE, 0);

    reg_button = gtk_button_new_with_label("Register");
    gtk_box_pack_start(GTK_BOX(vbox), reg_button, FALSE, FALSE, 0);

    g_signal_connect(reg_button, "clicked", G_CALLBACK(on_register_clicked), NULL);

    gtk_widget_show_all(container);
}



static void build_login_ui(GtkWidget *container) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(vbox, GTK_ALIGN_CENTER);

    gtk_container_add(GTK_CONTAINER(container), vbox);

    GtkWidget *label = gtk_label_new("Enter Master Key:");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    login_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(login_entry), FALSE);
    // Use a standard ASCII character for the invisible char to avoid encoding issues
    gtk_entry_set_invisible_char(GTK_ENTRY(login_entry), '*');
    gtk_box_pack_start(GTK_BOX(vbox), login_entry, FALSE, FALSE, 0);

    login_button = gtk_button_new_with_label("Login");
    gtk_box_pack_start(GTK_BOX(vbox), login_button, FALSE, FALSE, 10);

    // Connect the Enter key to trigger login
    g_signal_connect(login_entry, "activate", G_CALLBACK(on_login_clicked), NULL);
    g_signal_connect(login_button, "clicked", G_CALLBACK(on_login_clicked), NULL);

    // Create lockout label
    lockout_label = gtk_label_new("");
    gtk_label_set_justify(GTK_LABEL(lockout_label), GTK_JUSTIFY_CENTER);
    gtk_widget_set_margin_top(lockout_label, 10);
    gtk_widget_set_no_show_all(lockout_label, TRUE);
    gtk_widget_set_halign(lockout_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(vbox), lockout_label, FALSE, FALSE, 0);

    // Create progress bar for lockout countdown
    progress_bar = gtk_progress_bar_new();
    gtk_widget_set_size_request(progress_bar, 250, 10);
    gtk_widget_set_margin_top(progress_bar, 5);
    gtk_widget_set_no_show_all(progress_bar, TRUE);
    gtk_widget_set_halign(progress_bar, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(vbox), progress_bar, FALSE, FALSE, 0);

    // Initially hide the lockout UI elements
    gtk_widget_hide(lockout_label);
    gtk_widget_hide(progress_bar);

    gtk_widget_show_all(container);
}

static void on_add_entry_response(GtkDialog *dialog, gint response_id, gpointer user_data) {
    (void)dialog;
    (void)user_data;
    if (response_id == GTK_RESPONSE_OK) {

        GtkWidget *service_entry = g_object_get_data(G_OBJECT(dialog), "service_entry");
        GtkWidget *username_entry = g_object_get_data(G_OBJECT(dialog), "username_entry");
        GtkWidget *email_entry = g_object_get_data(G_OBJECT(dialog), "email_entry");
        GtkWidget *password_entry = g_object_get_data(G_OBJECT(dialog), "password_entry");
        GtkWidget *password_confirm_entry = g_object_get_data(G_OBJECT(dialog), "password_confirm_entry");


        if (!service_entry || !username_entry || !password_entry || !password_confirm_entry) {
            log_message_error("Missing entry widgets!");
            return;
        }


        const char *service = gtk_entry_get_text(GTK_ENTRY(service_entry));
        const char *username = gtk_entry_get_text(GTK_ENTRY(username_entry));
        const char *email = email_entry ? gtk_entry_get_text(GTK_ENTRY(email_entry)) : "";
        const char *password = gtk_entry_get_text(GTK_ENTRY(password_entry));
        const char *password_confirm = gtk_entry_get_text(GTK_ENTRY(password_confirm_entry));


        if (!service || !username || !password || strlen(service) == 0 || strlen(username) == 0 || strlen(password) == 0) {
            GtkWidget *err_dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                GTK_BUTTONS_OK, "Service, Username, and Password cannot be empty.");
            gtk_dialog_run(GTK_DIALOG(err_dialog));
            gtk_widget_destroy(err_dialog);
            return;
        }

        if (strcmp(password, password_confirm) != 0) {
            GtkWidget *err_dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                GTK_BUTTONS_OK, "Passwords do not match.");
            gtk_dialog_run(GTK_DIALOG(err_dialog));
            gtk_widget_destroy(err_dialog);
            return;
        }


        Password_Storing new_entry;
        strncpy(new_entry.Service, service, sizeof(new_entry.Service) - 1);
        new_entry.Service[sizeof(new_entry.Service) - 1] = '\0';
        strncpy(new_entry.Username, username, sizeof(new_entry.Username) - 1);
        new_entry.Username[sizeof(new_entry.Username) - 1] = '\0';
        strncpy(new_entry.Mail, email ? email : "", sizeof(new_entry.Mail) - 1);
        new_entry.Mail[sizeof(new_entry.Mail) - 1] = '\0';
        strncpy(new_entry.Password, password, sizeof(new_entry.Password) - 1);
        new_entry.Password[sizeof(new_entry.Password) - 1] = '\0';


        log_message_info("Adding new entry: %s|%s|%s",
                 new_entry.Service, new_entry.Username, new_entry.Mail);

        add_entry(&entries, new_entry);

        if (master_key[0] == '\0') {
            log_message_error("Master key is not initialized.");
            GtkWidget *err_dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                GTK_BUTTONS_OK, "Master key is not initialized.");
            gtk_dialog_run(GTK_DIALOG(err_dialog));
            gtk_widget_destroy(err_dialog);
            gtk_widget_destroy(GTK_WIDGET(dialog));
            return;
        }

        log_message_info("Attempting to save entries to file...");
        save_entries_to_file(entries, (const unsigned char *)master_key);
        log_message_info("Save operation completed");

        GtkListStore *store = g_object_get_data(G_OBJECT(window), "entries_store");
        if (store) {
            refresh_entries_list(store);
        } else {
            log_message_error("Could not find entries store!");
        }
    }
    gtk_widget_destroy(GTK_WIDGET(dialog));
}



static void on_generate_password_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkWidget *dialog = GTK_WIDGET(user_data);
    GtkWidget *password_entry = g_object_get_data(G_OBJECT(dialog), "password_entry");
    GtkWidget *password_confirm_entry = g_object_get_data(G_OBJECT(dialog), "password_confirm_entry");

    char *new_password = generate_random_password(50);
    if (new_password) {
        gtk_entry_set_text(GTK_ENTRY(password_entry), new_password);
        gtk_entry_set_text(GTK_ENTRY(password_confirm_entry), new_password);
        free(new_password);
    }
}

static void on_add_entry_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    (void)user_data;
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Add Entry",
                                                   GTK_WINDOW(window),
                                                   GTK_DIALOG_MODAL,
                                                   "_Add", GTK_RESPONSE_OK,
                                                   "_Cancel", GTK_RESPONSE_CANCEL,
                                                   NULL);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 6);
    gtk_container_add(GTK_CONTAINER(content_area), grid);

    GtkWidget *service_label = gtk_label_new("Service:");
    GtkWidget *service_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), service_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), service_entry, 1, 0, 1, 1);

    GtkWidget *username_label = gtk_label_new("Username:");
    GtkWidget *username_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), username_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), username_entry, 1, 1, 1, 1);

    GtkWidget *email_label = gtk_label_new("Email:");
    GtkWidget *email_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), email_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), email_entry, 1, 2, 1, 1);

    GtkWidget *password_label = gtk_label_new("Password:");
    GtkWidget *password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(password_entry), '*');
    gtk_grid_attach(GTK_GRID(grid), password_label, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), password_entry, 1, 3, 1, 1);

    GtkWidget *generate_password_button = gtk_button_new_with_label("Generate Password");
    gtk_grid_attach(GTK_GRID(grid), generate_password_button, 2, 3, 1, 1);

    GtkWidget *password_confirm_label = gtk_label_new("Confirm Password:");
    GtkWidget *password_confirm_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(password_confirm_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(password_confirm_entry), '*');
    gtk_grid_attach(GTK_GRID(grid), password_confirm_label, 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), password_confirm_entry, 1, 4, 1, 1);

    g_object_set_data(G_OBJECT(dialog), "service_entry", service_entry);
    g_object_set_data(G_OBJECT(dialog), "username_entry", username_entry);
    g_object_set_data(G_OBJECT(dialog), "email_entry", email_entry);
    g_object_set_data(G_OBJECT(dialog), "password_entry", password_entry);
    g_object_set_data(G_OBJECT(dialog), "password_confirm_entry", password_confirm_entry);

    g_signal_connect(generate_password_button, "clicked", G_CALLBACK(on_generate_password_clicked), dialog);

    g_signal_connect(dialog, "response", G_CALLBACK(on_add_entry_response), NULL);

    gtk_widget_show_all(dialog);
}



static void on_delete_entry_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkTreeSelection *selection = GTK_TREE_SELECTION(user_data);
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gchar *service;
        gchar *username;
        gtk_tree_model_get(model, &iter,
                           0, &service,
                           1, &username,
                           -1);

        if (delete_entry(&entries, service, username)) {
            save_entries_to_file(entries, (const unsigned char *)master_key);

            GtkListStore *store = g_object_get_data(G_OBJECT(window), "entries_store");
            refresh_entries_list(store);

            GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_INFO,
                GTK_BUTTONS_OK, "Entry deleted successfully.");
            gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        } else {
            GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                GTK_BUTTONS_OK, "Entry not found.");
            gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        }

        g_free(service);
        g_free(username);
    } else {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
            GTK_BUTTONS_OK, "No entry selected to delete.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    }
}

static void refresh_entries_list(GtkListStore *store) {
    gtk_list_store_clear(store);

    liste temp = entries;
    while (temp != NULL) {
        GtkTreeIter iter;
        gtk_list_store_append(store, &iter);
        gtk_list_store_set(store, &iter,
                           0, temp->P.Service,
                           1, temp->P.Username,
                           2, temp->P.Mail,
                           3, temp->P.Password,
                           4, FALSE,
                           -1);
        temp = temp->next;
    }
}

static void password_cell_data_func(GtkTreeViewColumn *col, GtkCellRenderer *renderer, GtkTreeModel *model,
                                    GtkTreeIter *iter, gpointer data) {
    (void)col;
    (void)data;
    gchar *password;
    gboolean visible;
    gtk_tree_model_get(model, iter, 3, &password, 4, &visible, -1);

    int len = (int)strlen(password);
    char *masked = g_malloc((gsize)(len + 1));
    memset(masked, '*', (size_t)len);
    masked[len] = '\0';
    if (!visible) {
        g_object_set(renderer, "text", masked, NULL);
    } else {
        g_object_set(renderer, "text", password, NULL);
    }
    g_free(masked);
    g_free(password);
}

static void toggle_cell_data_func(GtkTreeViewColumn *col, GtkCellRenderer *renderer, GtkTreeModel *model,
                                 GtkTreeIter *iter, gpointer data) {
    (void)col;
    (void)data;
    gboolean visible;
    gtk_tree_model_get(model, iter, 4, &visible, -1);
    g_object_set(renderer, "active", visible, NULL);
}

static void on_password_toggle_toggled(GtkCellRendererToggle *renderer, gchar *path_str, gpointer user_data) {
    (void)renderer;
    GtkListStore *store = GTK_LIST_STORE(user_data);
    GtkTreePath *path = gtk_tree_path_new_from_string(path_str);
    GtkTreeIter iter;

    if (gtk_tree_model_get_iter(GTK_TREE_MODEL(store), &iter, path)) {
        gboolean visible;
        gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 4, &visible, -1);
        visible = !visible;
        gtk_list_store_set(store, &iter, 4, visible, -1);
    }

    gtk_tree_path_free(path);
}


static guint clipboard_timeout_id = 0;

static gboolean clear_clipboard_again(gpointer user_data) {
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        CloseClipboard();
    }
    return G_SOURCE_REMOVE;
}

static gboolean clear_clipboard_timeout(gpointer data) {

    GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    

    gtk_clipboard_set_text(clipboard, "", 0);
    gtk_clipboard_set_text(primary, "", 0);
    gtk_clipboard_clear(clipboard);
    gtk_clipboard_clear(primary);
    
    // Clear Windows clipboard using Windows API
    if (OpenClipboard(NULL)) {
        // Clear the clipboard data
        EmptyClipboard();
        
        // Add an empty text item to replace any existing clipboard data
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, 1);
        if (hMem) {
            char *pMem = (char*)GlobalLock(hMem);
            if (pMem) {
                *pMem = '\0'; // Empty string
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
            }
            GlobalFree(hMem);
        }
        
        // Close the clipboard
        CloseClipboard();
        
        // For Windows 10+ clipboard history, we need to clear the clipboard again after a short delay
        // to ensure the history is cleared
        g_timeout_add(100, clear_clipboard_again, NULL);
    }
    
    // Update status bar
    GtkWidget *statusbar = GTK_WIDGET(data);
    if (statusbar && GTK_IS_STATUSBAR(statusbar)) {
        gtk_statusbar_pop(GTK_STATUSBAR(statusbar), 0);
        guint context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "clipboard");
        gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, "Clipboard cleared for security");
    }
    
    log_message_info("Clipboard cleared after timeout");
    
    // Clear our timeout ID
    clipboard_timeout_id = 0;
    
    return G_SOURCE_REMOVE;
}

static void on_copy_password_toggled(GtkCellRendererToggle *renderer, gchar *path_str, gpointer user_data) {
    (void)renderer; // Mark as unused
    GtkListStore *store = GTK_LIST_STORE(user_data);
    GtkTreePath *path = gtk_tree_path_new_from_string(path_str);
    GtkTreeIter iter;
    gtk_tree_model_get_iter(GTK_TREE_MODEL(store), &iter, path);
    
    // Get the password from the model (column 3)
    gchar *password = NULL;
    gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 3, &password, -1);
    
    if (password && *password) {

        GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
        gtk_clipboard_set_text(clipboard, password, -1);
        

        if (clipboard_timeout_id > 0) {
            g_source_remove(clipboard_timeout_id);
            clipboard_timeout_id = 0;
        }
        

        GtkWidget *statusbar = g_object_get_data(G_OBJECT(store), "statusbar");
        clipboard_timeout_id = g_timeout_add_seconds(30, clear_clipboard_timeout, statusbar);
        

        if (statusbar && GTK_IS_STATUSBAR(statusbar)) {
            gtk_statusbar_pop(GTK_STATUSBAR(statusbar), 0);
            guint context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "clipboard");
            gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, "Password copied to clipboard (will clear in 30s)");
        }
        
        log_message_info("Password copied to clipboard");
    }
    
    g_free(password);
    gtk_tree_path_free(path);
}



static gboolean reset_idle_timer(GtkWidget *widget, GdkEvent *event, gpointer user_data) {
    (void)widget;
    (void)event;
    (void)user_data;  // We're not using the user_data parameter
    
    if (idle_timer_id != 0) {
        g_source_remove(idle_timer_id);
    }
    idle_timer_id = g_timeout_add_seconds(300, idle_timeout_callback, NULL); // 5 minute timeout
    return FALSE; // Let other handlers process the event
}

static gboolean update_lockout_ui(gpointer user_data) {
    gint64 now = g_get_real_time() / G_USEC_PER_SEC;
    gint remaining = (gint)(lockout_end_time - now);
    
    if (remaining <= 0) {
        // Lockout period over
        gtk_widget_set_sensitive(login_entry, TRUE);
        gtk_widget_set_sensitive(login_button, TRUE);
        gtk_widget_hide(lockout_label);
        gtk_widget_hide(progress_bar);
        failed_login_attempts = 0;
        return G_SOURCE_REMOVE;
    }
    
    // Update progress bar (0.0 to 1.0)
    gdouble fraction = (gdouble)remaining / LOCKOUT_DURATION;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), 1.0 - fraction);
    
    // Update label with remaining time
    gchar *message = g_strdup_printf("Too many failed attempts. Please wait %d:%02d", 
                                   remaining / 60, remaining % 60);
    gtk_label_set_text(GTK_LABEL(lockout_label), message);
    g_free(message);
    
    return G_SOURCE_CONTINUE;
}

static void start_lockout_ui() {
    gtk_widget_set_sensitive(login_entry, FALSE);
    gtk_widget_set_sensitive(login_button, FALSE);
    
    // Set lockout end time (current time + LOCKOUT_DURATION seconds)
    lockout_end_time = (g_get_real_time() / G_USEC_PER_SEC) + LOCKOUT_DURATION;
    
    // Show and initialize progress bar
    gtk_widget_show(lockout_label);
    gtk_widget_show(progress_bar);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), 1.0);
    
    // Start timer to update UI every second
    if (lockout_timer_id != 0) {
        g_source_remove(lockout_timer_id);
    }
    lockout_timer_id = g_timeout_add(1000, update_lockout_ui, NULL);
    
    // Initial update
    update_lockout_ui(NULL);
}

static void start_idle_timer() {
    if (idle_timer_id != 0) {
        g_source_remove(idle_timer_id);
    }
    idle_timer_id = g_timeout_add_seconds(IDLE_TIMEOUT_SECONDS, idle_timeout_callback, NULL);
}

static void build_main_ui(GtkWidget *container) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(container), vbox);

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_halign(hbox, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    GtkWidget *add_button = gtk_button_new_with_label("Add Entry");
    gtk_widget_set_name(add_button, "add-button");
    
    GtkWidget *delete_button = gtk_button_new_with_label("Delete Entry");
    gtk_widget_set_name(delete_button, "delete-button");
    
    GtkWidget *modify_button = gtk_button_new_with_label("Modify Entry");
    gtk_widget_set_name(modify_button, "modify-button");
    
    gtk_box_pack_start(GTK_BOX(hbox), add_button, FALSE, FALSE, 6);
    gtk_box_pack_start(GTK_BOX(hbox), modify_button, FALSE, FALSE, 6);
    gtk_box_pack_start(GTK_BOX(hbox), delete_button, FALSE, FALSE, 6);

    GtkWidget *treeview = gtk_tree_view_new();
    gtk_box_pack_start(GTK_BOX(vbox), treeview, TRUE, TRUE, 0);

    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Service", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Username", renderer, "text", 1, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Mail", renderer, "text", 2, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

    GtkCellRenderer *password_renderer = gtk_cell_renderer_text_new();
    GtkCellRendererToggle *toggle_renderer = GTK_CELL_RENDERER_TOGGLE(gtk_cell_renderer_toggle_new());

    GtkTreeViewColumn *password_column = gtk_tree_view_column_new();
    gtk_tree_view_column_set_title(password_column, "Password");

    gtk_tree_view_column_pack_start(password_column, password_renderer, TRUE);
    gtk_tree_view_column_pack_start(password_column, GTK_CELL_RENDERER(toggle_renderer), FALSE);

    gtk_tree_view_column_set_cell_data_func(password_column, password_renderer,
                                            password_cell_data_func, NULL, NULL);
    gtk_tree_view_column_set_cell_data_func(password_column, GTK_CELL_RENDERER(toggle_renderer),
                                            toggle_cell_data_func, NULL, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), password_column);

    GtkCellRendererToggle *copy_toggle = GTK_CELL_RENDERER_TOGGLE(gtk_cell_renderer_toggle_new());
    GtkTreeViewColumn *copy_column = gtk_tree_view_column_new();
    gtk_tree_view_column_set_title(copy_column, "Copy");
    gtk_tree_view_column_pack_start(copy_column, GTK_CELL_RENDERER(copy_toggle), TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), copy_column);


    GtkListStore *store = gtk_list_store_new(5,
                                             G_TYPE_STRING,
                                             G_TYPE_STRING,
                                             G_TYPE_STRING,
                                             G_TYPE_STRING,
                                             G_TYPE_BOOLEAN);

    gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));
    g_object_unref(store);

    g_object_set_data(G_OBJECT(window), "entries_store", store);

    refresh_entries_list(store);

    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

    g_signal_connect(add_button, "clicked", G_CALLBACK(on_add_entry_clicked), NULL);
    g_signal_connect(delete_button, "clicked", G_CALLBACK(on_delete_entry_clicked), selection);
    g_signal_connect(modify_button, "clicked", G_CALLBACK(on_modify_entry_clicked), selection);
    g_signal_connect(toggle_renderer, "toggled", G_CALLBACK(on_password_toggle_toggled), store);
    g_signal_connect(copy_toggle, "toggled", G_CALLBACK(on_copy_password_toggled), store);

    GtkWidget *statusbar = gtk_statusbar_new();
    gtk_box_pack_end(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);
    
    g_object_set_data_full(G_OBJECT(store), "statusbar", statusbar, NULL);

    gtk_widget_show_all(container);
}

static void show_main_ui() {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "main");
}

static void show_login_ui() {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}

static void show_registration_ui() {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "register");
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Password Manager");
    gtk_window_set_default_size(GTK_WINDOW(window), 700, 400);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    stack = gtk_stack_new();
    gtk_container_add(GTK_CONTAINER(window), stack);

    GtkWidget *login_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    build_login_ui(login_container);
    gtk_stack_add_named(GTK_STACK(stack), login_container, "login");

    GtkWidget *register_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    build_registration_ui(register_container);
    gtk_stack_add_named(GTK_STACK(stack), register_container, "register");

    GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    build_main_ui(main_container);
    gtk_stack_add_named(GTK_STACK(stack), main_container, "main");

    gtk_widget_show_all(window);

    if (access(VERIFIER_FILE, F_OK) != -1) {
        show_login_ui();
    } else {
        show_registration_ui();
    }

    gtk_widget_add_events(window,
        GDK_KEY_PRESS_MASK |
        GDK_BUTTON_PRESS_MASK |
        GDK_POINTER_MOTION_MASK);

    g_signal_connect(window, "key-press-event", G_CALLBACK(reset_idle_timer), NULL);
    g_signal_connect(window, "button-press-event", G_CALLBACK(reset_idle_timer), NULL);
    g_signal_connect(window, "motion-notify-event", G_CALLBACK(reset_idle_timer), NULL);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    start_idle_timer();
    gtk_main();

    if (idle_timer_id != 0) {
        g_source_remove(idle_timer_id);
        idle_timer_id = 0;
    }

    return 0;
}

