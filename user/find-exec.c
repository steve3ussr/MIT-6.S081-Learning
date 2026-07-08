#include "kernel/types.h"
#include "user/user.h"
#include "kernel/stat.h"
#include "kernel/fs.h"


void find(int argc, char *argv[]) {
    // check arg, must contain arg-path, arg-name
    if (argc != 3) {
        fprintf(2, "Usage: find <path> <name>\n", 27);
        exit(1);
    }
    // printf("looking for name %s in dir %s\n", argv[2], argv[1]);
    char buf[512], *p;
    int fd;
    struct dirent de;
    struct stat st;


    if((fd = open(argv[1], 0)) < 0){
        fprintf(2, "find: cannot open %s as a path\n", argv[1]);
        exit(1);
    }

    if(fstat(fd, &st) < 0){
        fprintf(2, "find: cannot stat %s\n", argv[1]);
        close(fd);
        exit(1);
    }

    if (st.type != T_DIR) {
        fprintf(2, "Usage: find <path> <name>\n", 27);
        close(fd);
        exit(1);
    }

    while(read(fd, &de, sizeof(de)) == sizeof(de)){
        if(de.inum == 0)
            continue;
        // for (int i=0; i<512; i++) {buf[i]=0;}
        // strcpy(buf, argv[1]);
        // p = buf+strlen(buf);
        // *p++ = '/';
        // printf("FOUND %s\n", de.name);
        // memmove(p, de.name, DIRSIZ);
        // p[DIRSIZ] = 0;
        // printf("buf: %s\n", buf);

        strcpy(buf, argv[1]);
        p = buf+strlen(argv[1]);
        *p++ = '/';
        memmove(p, de.name, DIRSIZ);
        p[DIRSIZ] = 0;
        // printf("FOUND %s\n", buf);

        if(stat(buf, &st) < 0){
            printf("ls: cannot stat %s\n", buf);
            continue;
        }
        if (st.type==T_FILE) {
            if (strcmp(argv[2], de.name)){
                continue;
            } else {
                fprintf(1, "%s\n", buf);
            }
        } else if (st.type==T_DEVICE) {
            continue;
        } else {
            if (strcmp(".", de.name)==0) continue;
            if (strcmp("..", de.name)==0) continue;

            char *args[4] = { argv[0], buf, argv[2], 0};
            // printf("try exec find with args: %s, %s, %s\n", args[0], args[1], args[2]);
            if (fork()==0) {
                exec(args[0], args);
                // printf("oh no\n");
            }
            
        }

    }

        
    

 
    wait(0);
    close(fd);
    exit(0);
}