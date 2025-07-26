#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

void setup() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    system("echo Welcome");
}

int main(int argc, char **argv) {
    setup();
#if defined(FLAG_LEAK)
    char flagbuf[64];
    int fd = open("flag.txt", O_RDONLY);
    if (fd <= -1) {
        perror("open");
        goto exit;
    }
    read(fd, flagbuf, sizeof(flagbuf));
    close(fd);
#endif

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
exit:
    return 0;
}

