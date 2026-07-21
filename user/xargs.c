#include "kernel/types.h"
#include "kernel/param.h"
#include "user/user.h"


#define MAXLEN 512


int main(int argc, char *argv[]){
    // get stdin
    char buf[MAXLEN];
    char *p_buf = buf;
    int n_stdin;
    while ((n_stdin = read(0, p_buf, MAXLEN)) > 0) p_buf += n_stdin;
    // DEBUG: print stdin
    // printf("\n[DEBUG]  buf: %s\n", buf);


    // parse stdin -> list
    char *list[MAXARG];
    int lo=0, i_list=0, max_hi=strlen(buf);
    for (int hi=0; hi<max_hi; hi++) {
        if ((buf[hi] == '\n') || (buf[hi] == ' ')){
            list[i_list] = malloc(hi-lo+1);
            memmove(list[i_list++], &(buf[lo]), hi-lo);
            lo = hi+1;
        }
    }

    // DEBUG: print list
    // for(int i=0; i<MAXARG; i++) { if (list[i]==0) break; printf("\n[DEBUG]  buf list[%d]: %s\n", i, list[i]); }


    for(int i=0; i<i_list; i++) {

        if (fork()==0) {
            /*
            Example: argc=3, argv={"xargs", "grep", "hello"}
            args should be {"grep", "hello", "string from stdin", 0}

            args length: argc+1
            argc[argc]     = 0
            argc[0:argc-1] = argv[1:argc]
            argc[argc-1]   = "string from stdin"
            */
            char *args[argc+1]; 
            args[argc]=0; 
            args[argc-1]=list[i];
            for (int j=0; j<argc-1; j++) {args[j]=argv[j+1];}
            exec(args[0], args);
        }
        wait(0);

    }
    exit(0);
}




