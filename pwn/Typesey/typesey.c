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

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    return;
}


uint64_t read_u64_val() {
    char inputbuf[32];
    memset(inputbuf, 0, sizeof(inputbuf));
    printf("> ");
    fgets(inputbuf, sizeof(inputbuf)-1, stdin);
    uint64_t outval = strtoull(inputbuf, NULL, 10);
    return outval;
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
    char hello_world_buf[] = "hello world";
    uint32_t hello_world_strlen = strlen(hello_world_buf);
    char readbuf[64];
    ssize_t nread = 0;
    memset(&readbuf, 0, sizeof(readbuf));

    setup();
    printf("Ok now you need to send me a bunch of data in different formats\n");
    printf("Errybody in the cubefarm getting typesey\n");


    printf("send me a 'hello world' without a null byte\n");
    printf("> ");
    nread = read(0, &readbuf, sizeof(readbuf));
    if (nread > hello_world_strlen) {
        printf("You sent too many bytes\n");
        DumpHex(&readbuf, (size_t)nread);
        goto exit;
    }
    if (0 != memcmp(&readbuf, &hello_world_buf, nread)) {
        printf("the number of bytes you sent was right, but not the contents\n");
        DumpHex(&readbuf, (size_t)nread);
        goto exit;
    }
    printf("correct!\n");

    memset(&readbuf, 0, sizeof(readbuf));
    printf("send me a 'hello world' with a null byte\n");
    printf("> ");
    nread = read(0, &readbuf, sizeof(readbuf));
    if (nread != hello_world_strlen+1) {
        printf("You sent the wrong number of bytes\n");
        DumpHex(&readbuf, (size_t)nread);
        goto exit;
    }
    if (0 != memcmp(&readbuf, &hello_world_buf, nread)) {
        printf("the number of bytes you sent was right, but not the contents\n");
        DumpHex(&readbuf, (size_t)nread);
        goto exit;
    }

    printf("correct!\n");

    uint64_t system_addr = (uint64_t)&system;
    printf("system %p\n", &system);
    printf("Enter the packed bytes of system's address\n");
    printf("> ");
    uint64_t user_system_val = 0;
    read(0, &user_system_val, sizeof(user_system_val));
    if (user_system_val != system_addr) {
        printf("the actual address was %p, better luck next time\n", (void*)system_addr);
        goto exit;
    }
    printf("correct!\n");

    uint64_t setvbuf_addr = (uint64_t)&setvbuf;
    printf("setvbuf %p\n", &setvbuf);
    printf("Enter the lower 4 bytes of setvbuf's address as a decimal unsigned integer\n");
    uint64_t user_setvbuf_lower_val = read_u64_val();
    uint64_t lower32_setvbuf = setvbuf_addr & 0xffffffff;
    if (user_setvbuf_lower_val != lower32_setvbuf) {
        printf("The actual value I was expecting was %u, better luck next time\n", (uint32_t)lower32_setvbuf);
        goto exit;
    }
    printf("correct!\n");

    uint64_t write_addr = (uint64_t)&write;
    printf("write %s\n", (char*)&write_addr);
    printf("Enter address of write as a decimal uint64_t\n");
    uint64_t user_write_val = read_u64_val();
    if (user_write_val != write_addr) {
        printf("The actual value I was expecting was %zu, better luck next time\n", write_addr);
        goto exit;
    }
    printf("correct!\n");

    printf("success!\n");
    print_flag();

exit:
    return 0;
}

