#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

void vuln(void);

void* g_buf = NULL;

#define PIVOT_BUF_SIZE 4000

int main(){
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    fflush(stdout);
    puts("welcome to the pivot dojo\n");
    g_buf = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);//malloc(PIVOT_BUF_SIZE);
    g_buf = (void*)((size_t)g_buf+0x8000);
    printf("A gift: %p\n", g_buf);
    read(0, g_buf, PIVOT_BUF_SIZE);
    vuln();
    return 0;
}

void vuln(void){
    char buf [32];
    memset(buf, 0, sizeof(buf));
    printf("give me your message: ");
    read(0, buf, 48);
    return;
}

asm("poprdi:"
    "pop %rdi;"
    "ret;");

asm("poprbp:"
    "pop %rbp;"
    "ret;");

