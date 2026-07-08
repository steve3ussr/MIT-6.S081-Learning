#include "kernel/types.h"
#include "user/user.h"


int pingpong(int argc, char *argv[])
{
    int p1[2]; pipe(p1);
    int p2[2]; pipe(p2);

    if (fork() == 0) {
        close(p1[1]);
        close(p2[0]);
        
        // pingpong: read from p1[0], write to p2[1]
        int pid = getpid();
        char buf[10];
        read(p1[0], &buf, 1);
        printf("%d: received ping\n", pid);
        write(p2[1], &buf, 1);

        // close
        close(p1[0]);
        close(p2[1]);
        exit(0);
    }

    close(p1[0]);
    close(p2[1]);

    // pingpong: read from p2[0], write to p1[1]
    int pid = getpid();
    char buf[10];
    buf[0] = 'A';
    write(p1[1], &buf, 1);
    read(p2[0], &buf, 1);
    printf("%d: received pong\n", pid);
    


    // close
    wait(0);
    close(p2[0]);
    close(p1[1]);
    exit(0); 
}