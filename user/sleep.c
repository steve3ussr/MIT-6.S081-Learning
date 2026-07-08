#include "kernel/types.h"
#include "user/user.h"


int main(int argc, char *argv[]) {
    // check only 1 argv
    if (argc != 2) {
        fprintf(2, "Usage: sleep <positive int>\n");
        exit(1);
    }

    // check argv format
    int x = atoi(argv[1]);
    if (x <= 0) {
        fprintf(2, "Usage: sleep <positive int>\n");
        exit(1);
    }
    sleep(x);
    exit(0);
}