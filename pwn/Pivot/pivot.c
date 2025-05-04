#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <syscall.h>


void vuln(void);

void setup_unbuffered(void) {
    // don't buffer inputs in the heap
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return;
}


int main(){
    setup_unbuffered();
    puts("Let me see you pivot");
    fflush(stdout);
    void* pivotbuf = malloc(0xa000);
    if (pivotbuf == NULL) {
        return 1;
    }
    printf("A gift %p\n", pivotbuf);
    vuln();
    return 0;
}

void vuln(void){
    char buf [32];
    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf)+(sizeof(void*)*2));
    return;
}

asm("poprdi:"
    "pop %rdi;"
    "ret;");

asm("poprbp:"
    "pop %rbp;"
    "ret;");

