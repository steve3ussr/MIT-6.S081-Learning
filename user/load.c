#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/sysinfo.h"



struct sysinfo p;


int main(void)
{
    sysinfo(&p);
    printf("load: %s    %s    %s\n", 
        p.load1, 
        p.load5,
        p.load15);
    exit(0);

}
