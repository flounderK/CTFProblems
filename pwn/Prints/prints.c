#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void setup() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    system("echo Welcome");
}

int main(int argc, char **argv) {
    setup();
    char s[48];
    for (;;) {
        memset(s, 0, sizeof s);
        puts("Print something special");
        printf(" > ");
        read(0, &s, sizeof s);
        if (strncmp(s, "quit", sizeof("quit")-1) == 0) {
            break;
        }
        printf(s);
        s[0] = 0;
    }
    return 0;
}

