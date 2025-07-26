#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>

void setup() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

uint64_t read_hex_val() {
    char inputbuf[32];
    memset(inputbuf, 0, sizeof(inputbuf));
    printf("> ");
    fgets(inputbuf, sizeof(inputbuf)-1, stdin);
    uint64_t outval = strtoull(inputbuf, NULL, 16);
    return outval;
}


void print_flag() {
    char flagbuf[64];
    int fd = open("flag.txt", O_RDONLY);
    if (fd <= -1) {
        perror("open");
        goto exit;
    }
    ssize_t nread = read(fd, flagbuf, sizeof(flagbuf));
    close(fd);
    write(1, flagbuf, nread);
exit:
    return;
}

size_t get_libc_base() {
    uint32_t* curr_addr = (uint32_t*)((size_t)&system & ~0xfff);
    while (*curr_addr != 0x464c457f) {
        curr_addr = (uint32_t*)((size_t)curr_addr-0x1000);
    }
    return (size_t)curr_addr;
}


int main(int argc, char **argv) {
    setup();

    uint64_t system_addr = (uint64_t)&system;
    printf("setvbuf %p\n", &setvbuf);
    printf("Enter the address of system\n");
    uint64_t user_system_val = read_hex_val();
    if (user_system_val != system_addr) {
        printf("the actual address was %p, better luck next time\n", (void*)system_addr);
        goto exit;
    }
    size_t libc_base = get_libc_base();
    printf("Enter the base address of libc\n");
    uint64_t user_libc_base_val = read_hex_val();
    if (user_libc_base_val != libc_base) {
        printf("the actual address was %p, better luck next time\n", (void*)libc_base);
        goto exit;
    }

    printf("success!\n");
    print_flag();

exit:
    return 0;
}

