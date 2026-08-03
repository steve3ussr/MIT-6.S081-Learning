#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"


int main(int argc, char **argv) {
    int x = atoi(argv[1]);
    printf("grow %d bytes\n", x);
    print_pagetable();
    sbrk(x);
    print_pagetable();
    sbrk(-x);
    print_pagetable();
    exit(0);
}