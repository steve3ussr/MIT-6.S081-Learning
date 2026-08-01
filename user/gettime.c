#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"


int main() {
    int upid = ugetpid();
    int utime = ugettime();
    printf("user\t syscall pid=%d, uptime=%d\n", upid, utime);

    int pid = getpid();
    int time = uptime();
    printf("\t syscall pid=%d, uptime=%d\n", pid, time);
    if ((upid==pid) && (utime==time)) {
        printf("===== OK =====\n");
    } else {
        printf("xxxxx ERROR xxxxx\n");
    }
    exit(0);
}