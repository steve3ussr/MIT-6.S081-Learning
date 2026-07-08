#include "kernel/types.h"
#include "user/user.h"


#define MAXLEN 35


int main(int argc, char *argv[])
{
    int p[2];
    pipe(p);

    // init buf (2-35)
    int i, buf[MAXLEN]; for (i=0; i<MAXLEN; i++){buf[i]=0;} i=0;
    for (int tmp=2; tmp<=35; tmp++) {buf[i++] = tmp;}
    int base = 36;  // make sure send 2-35 from start
    

    while (fork() == 0) {

        close(p[1]);  // unused Write-Only end in child

        // flush buffer, and receive array from pipe
        for (i=0; i<MAXLEN; i++){buf[i]=0;}
        i = 0;
        while (read(p[0], &(buf[i++]), 4) > 0) {}
        close(p[0]);

        // print the base, this is a prime
        base = buf[0];
        printf("prime %d\n", base);

        // after loop, i = array length
        // only 1 number in array means the parent layer has only 1 number too, 
        // and it must has been printed in parent process
        // this is the end
        for (i=0; i<MAXLEN; i++){if(buf[i]==0) break; }
        if (i==1) exit(0); 
             
        // otherwise, reopen the pipe
        // for current process: fork()!=0, then end loop and send numbers to pipe
        // for child process:   fork()==0, then receive from pipe
        pipe(p);
    }

    close(p[0]);  // unused Read-Only end in parent
    for (i=0; i<MAXLEN; i++){ // send all filtered number in parent layer
        if ((buf[i]!=0) && (buf[i]%base!=0)) {
            write(p[1], &(buf[i]), 4);
        }
    }

    close(p[1]);  // child process read will unblock when close this Read-Only end
    wait(0);
    exit(0);
}