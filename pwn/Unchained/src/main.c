#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>

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

void menu(void) {
    printf("This is it. No chains, no limitations\n");
    printf("1. read at index\n");
    printf("2. write at index\n");
    printf("3. exit\n");
    return;
}
#define MENU_REPEAT 0
#define MENU_VALID_START 1
#define MENU_READ 1
#define MENU_WRITE 2
#define MENU_EXIT 3


uint32_t g_global_buffer[10];

void handle_read(void) {
    printf("index: \n");
    long long index = read_input_longlong();
    uint32_t read_val = g_global_buffer[index];
    printf("%u\n", read_val);
}

void handle_write(void) {
    printf("index: \n");
    long long index = read_input_longlong();
    printf("value: \n");
    long long value = read_input_longlong();
    g_global_buffer[index] = (uint32_t)value;
    return;
}


void vuln(void) {
    long long choice = 0;
    bool do_end = false;

    while (!do_end) {
        choice = read_input_longlong();
        switch (choice) {
            case MENU_READ: {
                handle_read();
                break;
            }
            case MENU_WRITE: {
                handle_write();
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
    menu();
    memset(g_global_buffer, 0, sizeof(g_global_buffer));
    vuln();
    exit(1);

    return 0;
}
