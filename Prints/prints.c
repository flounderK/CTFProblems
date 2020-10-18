#include <stdio.h>
#include <unistd.h>
#include <string.h>

void setup() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    system("echo Welcome");
}

int main(int argc, char **argv) {
    setup();
    char s[20];
    for (;;) {
        memset(s, 0, sizeof s);
        puts("Print something special");
        printf(" > ");
        read(0, &s, 19);
        printf(s);
        s[0] = 0;
    }
}

