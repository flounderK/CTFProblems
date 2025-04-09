#include <stdio.h>
#include <string.h>

void vuln(void);

int main(){
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    puts("Finna ROP?");
    fflush(stdout);
    vuln();
    return 0;
}

void vuln(void){
    char buf [32];
    memset(buf, 0, sizeof(buf));
    fgets(buf, 0x100, stdin);
    return;
}

asm("poprdi:"
    "pop %rdi;"
    "ret;");

asm("poprbp:"
    "pop %rbp;"
    "ret;");

