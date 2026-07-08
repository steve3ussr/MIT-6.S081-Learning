#include "kernel/types.h"
#include "user/user.h"


int main(int argc, char *argv[]) {
    int x = uptime();
    printf("uptime: %d\n", x);
    exit(0);
}