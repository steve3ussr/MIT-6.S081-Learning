#include "kernel/types.h"
#include "user/user.h"
#include "kernel/stat.h"
#include "kernel/fs.h"


#define MAX_QUEUE 128

int match(char*, char*);
int matchhere(char*, char*);
int matchstar(int, char*, char*);

int match(char *re, char *text)
{
  if(re[0] == '^')
    return matchhere(re+1, text);
  do{  // must look at empty string
    if(matchhere(re, text))
      return 1;
  }while(*text++ != '\0');
  return 0;
}

// matchhere: search for re at beginning of text
int matchhere(char *re, char *text)
{
  if(re[0] == '\0')
    return 1;
  if(re[1] == '*')
    return matchstar(re[0], re+2, text);
  if(re[0] == '$' && re[1] == '\0')
    return *text == '\0';
  if(*text!='\0' && (re[0]=='.' || re[0]==*text))
    return matchhere(re+1, text+1);
  return 0;
}

// matchstar: search for c*re at beginning of text
int matchstar(int c, char *re, char *text)
{
  do{  // a * matches zero or more instances
    if(matchhere(re, text))
      return 1;
  }while(*text!='\0' && (*text++==c || c=='.'));
  return 0;
}




int main(int argc, char *argv[]) {
    // check arg, must contain arg-path, arg-name
    if (argc != 3) {
        fprintf(2, "Usage: find <path> <name>\n", 27);
        exit(1);
    }

    // init path
    char *queue[MAX_QUEUE]; for(int tmp=0; tmp<MAX_QUEUE; tmp++) {queue[tmp]=0;}
    queue[0] = malloc(512);
    strcpy(queue[0], argv[1]);


    while(fork()==0) {
        // printf("current layer queue: \n");
        for(int tmp=0; tmp<MAX_QUEUE; tmp++){
            if (queue[tmp]==0) break;
            // printf("\t%s\n", queue[tmp]);
        }



        char *new_queue[MAX_QUEUE]; for(int tmp=0; tmp<MAX_QUEUE; tmp++) {new_queue[tmp]=0;}
        int i_new_queue = 0;


        int fd;
        struct dirent de;
        struct stat st;
        char buf[512], *p;
        

        for(int tmp=0; tmp<MAX_QUEUE; tmp++){
            if (queue[tmp]==0) break;

            // make sure CAN recursively check queue[tmp]
            if((fd = open(queue[tmp], 0)) < 0){
                fprintf(2, "find: cannot open %s as a path\n", queue[tmp]);
                exit(1);
            }

            if(fstat(fd, &st) < 0){
                fprintf(2, "find: cannot stat %s\n", queue[tmp]);
                close(fd);
                exit(1);
            }

            if (st.type != T_DIR) {
                fprintf(2, "Usage: find <path> <name>\n", 27);
                close(fd);
                exit(1);
            }

            // looking for subpath of queue[tmp]
            // printf("Checking queue[%d] %s\n", tmp, queue[tmp]);
            while(read(fd, &de, sizeof(de)) == sizeof(de)){
                if(de.inum == 0) continue;
                // printf("\tfound subpath %s\n", de.name);
                
                for(int i=0; i<512; i++) {buf[i]=0;}    // 
                strcpy(buf, queue[tmp]);                //
                p = buf+strlen(queue[tmp]);             // flush buf, concat queue[tmp] and de.name
                *p++ = '/';                             // 
                memmove(p, de.name, DIRSIZ);            // 
                p[DIRSIZ] = 0;

                if(stat(buf, &st) < 0){
                    printf("ls: cannot stat %s\n", buf);
                    continue;
                }

                if (st.type==T_FILE) {
                    // non-regexp mode
                    // if (strcmp(argv[2], de.name)){
                    //     continue;
                    // } else {
                    //     fprintf(1, "%s\n", buf);
                    // }

                    // regexp mode
                    if (match(argv[2], de.name)){
                        fprintf(1, "%s\n", buf);
                    } else {
                        continue;
                    }
                    
                } else if (st.type==T_DEVICE) {
                    continue;
                } else {
                    if ((strcmp(".", de.name)==0) || (strcmp("..", de.name)==0)) continue;
                    new_queue[i_new_queue] = malloc(512);
                    strcpy(new_queue[i_new_queue], buf);
                    // printf("append %s to new_queue\n", new_queue[i_new_queue]);
                    i_new_queue++;
                }

            }
            close(fd);


        }
        
        // printf("current layer new_queue: \n");
        for(int tmp=0; tmp<MAX_QUEUE; tmp++){
            if (new_queue[tmp]==0) break;
            // printf("\t%s\n", new_queue[tmp]);
        }

        if (i_new_queue==0){exit(0);}
        for(int tmp=0; tmp<MAX_QUEUE; tmp++) {queue[tmp]=0;}
        for(int tmp=0; tmp<MAX_QUEUE; tmp++) {
            if (new_queue[tmp]==0) break;
            queue[tmp] = new_queue[tmp];
        }

        // printf("next layer queue: \n");
        for(int tmp=0; tmp<MAX_QUEUE; tmp++){
            if (queue[tmp]==0) break;
            // printf("\t%s\n", queue[tmp]);
        }


    }




    

        
    

    
    wait(0);
    for(int tmp=0; tmp<MAX_QUEUE; tmp++){
        if (queue[tmp]==0) break;
        free(queue[tmp]);
    }
    exit(0);
}