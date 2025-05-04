#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <stdlib.h>
#include <syscall.h>


int setup_filter(void){
    int res = -1;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto exit;
	}

    res = 0;
exit:
    return res;
}

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
    puts("Let's see you work around a small limitation");
    fflush(stdout);
    if (setup_filter() == -1) {
        return 1;
    }
    vuln();
    return 0;
}

void vuln(void){
    char buf [32];
    memset(buf, 0, sizeof(buf));
    read(0, buf, 0x100);
    return;
}

asm("poprdi:"
    "pop %rdi;"
    "ret;");

asm("poprbp:"
    "pop %rbp;"
    "ret;");

