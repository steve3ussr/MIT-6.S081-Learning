#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"


int main() {
    int upid = ugetpid();
    printf("user syscall pid: %d\n", upid);
    int pid = getpid();
    printf("syscall pid: %d\n", pid);
    print_pagetable();
    sbrk(1);
    print_pagetable();
    exit(0);
}