#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"


#define MAXLEN 35


int main(int argc, char *argv[])
{
    for(int i=0; i<50; i++) {
        if (fork()==0) {
            for(int j=0; j<100; j++) {sleep(1);}
            exit(0);
        }
    }
    while (wait(0) != -1) {}
    exit(0);

}

