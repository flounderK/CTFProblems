#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>


typedef struct _Contact {
    char* name;
    uint32_t name_length;
} Contact;

Contact* g_contact_list[10] = {0};
char* g_owner_name = NULL;
uint32_t g_owner_name_length = 0;

void setup_unbuffered(void) {
    // don't buffer inputs in the heap
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return;
}

long long read_input_longlong(void) {
    char inputbuf[32];
    memset(inputbuf, 0, sizeof(inputbuf));
    printf("> ");
    fgets(inputbuf, sizeof(inputbuf)-1, stdin);
    long long outval = strtol(inputbuf, NULL, 10);
    return outval;
}

void populate_owner_name(void) {
    if (g_owner_name != NULL) {
        printf("owner name already populated\n");
        goto exit;
    }
    printf("enter owner name length: \n");
    g_owner_name_length = (uint32_t)read_input_longlong();
    g_owner_name = (char*)malloc(g_owner_name_length);
    if (g_owner_name == NULL) {
        printf("failed to allocate owner name\n");
        exit(1);
    }
    memset(g_owner_name, 0, g_owner_name_length);

    printf("enter owner name: \n");
    read(0, g_owner_name, g_owner_name_length);
    char* cr_ptr = NULL;
    char* nl_ptr = NULL;
    while (1) {
        nl_ptr = strchr(g_owner_name, '\n');
        if (nl_ptr != NULL) {
            nl_ptr[0] = '\0';
        }
        cr_ptr = strchr(g_owner_name, '\r');
        if (cr_ptr != NULL) {
            cr_ptr[0] = '\0';
        }
        if (nl_ptr == NULL && cr_ptr == NULL) {
            break;
        }
    }
exit:
    return;
}


void menu(void) {
    printf("Welcome to my address book\n");
    printf("1. print owner name\n");
    printf("2. edit owner name\n");
    printf("3. print contact\n");
    printf("4. add contact\n");
    printf("5. delete contact\n");
    printf("6. edit contact\n");
    printf("8. exit\n");
    return;
}
#define MENU_REPEAT 0
#define MENU_VALID_START 1
#define MENU_PRINT_OWNER_NAME 1
#define MENU_EDIT_OWNER_NAME 2
#define MENU_PRINT_CONTACT 3
#define MENU_ADD_CONTACT 4
#define MENU_DELETE_CONTACT 5
#define MENU_EDIT_CONTACT 6
#define MENU_DELETE_OWNER_NAME 7
#define MENU_EXIT 8

void handle_print_owner_name(void) {
    if (g_owner_name == NULL) {
        printf("owner name is NULL\n");
        goto exit;
    }
    printf("%s's address book\n", g_owner_name);
exit:
    return;
}

void handle_edit_owner_name(void) {
    printf("enter new owner name: \n");
    read(0, g_owner_name, g_owner_name_length);
    printf("new owner name: %s\n", g_owner_name);
    return;
}

void handle_print_contact(void) {
    printf("index: \n");
    uint32_t index = (uint32_t)read_input_longlong();
    if (index < 0 || index > sizeof(g_contact_list) / sizeof(Contact*)) {
        printf("invalid index\n");
        goto exit;
    }

    Contact* contact = g_contact_list[index];
    if (contact == NULL) {
        printf("contact was empty\n");
        goto exit;
    }
    if (contact->name == NULL) {
        printf("contact name empty\n");
        goto exit;
    }
    printf("name: %s\n", contact->name);
exit:
    return;
}

void handle_add_contact(void) {
    printf("index: \n");
    uint32_t index = (uint32_t)read_input_longlong();
    if (index < 0 || index > sizeof(g_contact_list) / sizeof(Contact*)) {
        printf("invalid index\n");
        goto exit;
    }

    Contact* contact = g_contact_list[index];
    if (contact != NULL) {
        printf("contact already populated\n");
        goto exit;
    }

    contact = (Contact*)malloc(sizeof(Contact));
    if (contact == NULL) {
        perror("failed to allocate Contact");
        goto exit;
    }
    memset(contact, 0, sizeof(Contact));
    printf("contact name length: \n");
    contact->name_length = (uint32_t)read_input_longlong();

    contact->name = (char*)malloc(contact->name_length);
    if (contact->name == NULL) {
        perror("failed to allocate contact name");
        goto exit;
    }
    memset(contact->name, 0, contact->name_length);
    printf("enter contact name: \n");
    read(0, contact->name, contact->name_length);

exit:
    return;
}

void handle_delete_contact(void) {
    printf("index: \n");
    uint32_t index = (uint32_t)read_input_longlong();
    if (index < 0 || index > sizeof(g_contact_list) / sizeof(Contact*)) {
        printf("invalid index\n");
        goto exit;
    }

    Contact* contact = g_contact_list[index];
    if (contact == NULL) {
        printf("contact empty\n");
        goto exit;
    }

    if (contact->name != NULL) {
        free(contact->name);
    }

    free(contact);
    g_contact_list[index] = NULL;

exit:
    return;
}

void handle_edit_contact(void) {
    printf("index: \n");
    uint32_t index = (uint32_t)read_input_longlong();
    if (index < 0 || index > sizeof(g_contact_list) / sizeof(Contact*)) {
        printf("invalid index\n");
        goto exit;
    }

    Contact* contact = g_contact_list[index];
    if (contact == NULL) {
        printf("contact empty\n");
        goto exit;
    }

    if (contact->name == NULL) {
        printf("contact name empty\n");
        goto exit;
    }

    printf("enter new contact name: \n");
    read(0, contact->name, contact->name_length);
exit:
    return;
}

void handle_delete_owner_name(void) {
    if (g_owner_name == NULL) {
        printf("owner name is null\n");
        goto exit;
    }
    free(g_owner_name);
exit:
    return;
}


void vuln(void) {
    long long choice = 0;
    bool do_end = false;

    while (!do_end) {
        choice = read_input_longlong();
        switch (choice) {
            case MENU_PRINT_OWNER_NAME: {
                handle_print_owner_name();
                break;
            }
            case MENU_EDIT_OWNER_NAME: {
                handle_edit_owner_name();
                break;
            }
            case MENU_PRINT_CONTACT: {
                handle_print_contact();
                break;
            }
            case MENU_ADD_CONTACT: {
                handle_add_contact();
                break;
            }
            case MENU_DELETE_CONTACT: {
                handle_delete_contact();
                break;
            }
            case MENU_EDIT_CONTACT: {
                handle_edit_contact();
                break;
            }
            case MENU_DELETE_OWNER_NAME: {
                handle_delete_owner_name();
                break;
            }
            case MENU_EXIT: {
                do_end = true;
                break;
            }
            default:
               continue;
        }
        printf("\n");
    }

    return;
}


int main (int argc, char *argv[]) {
    setup_unbuffered();
    populate_owner_name();
    menu();
    vuln();
    exit(1);

    return 0;
}
