#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char **argv){
    if(argc != 2)
        goto err_usage;

    int sport = atoi(argv[1]);
    if(!(1024 <= sport && sport <= 65535))
        goto err_usage;

    // Step 1: create socket
    int fd;
    if((fd = connect(0, sport, 0, IPPROTO_UDP)) < 0){
        fprintf(2, "udp_server: connect() failed\n");
        exit(1);
    }
    printf("[UDP Echo Server] serving @ 10.0.2.15:%d \n", sport);

    // Step 2: recv
    char ibuf[128];
    uint32 raddr;
    uint16 rport;
    int len = 0;
    while (1) {
        memset(ibuf, 0, 128);
        raddr = 0;
        rport = 0;
        if ((len = recvfrom(fd, ibuf, sizeof(ibuf)-1, &raddr, &rport)) < 0){
            printf("[UDP Echo Server] recv error \n");
            continue;
        }
        printf("[UDP Echo Server] received a msg from remote host(%d.%d.%d.%d:%d): %s\n", ((raddr&0xFF000000)>>24), 
                                                          ((raddr&0x00FF0000)>>16), 
                                                          ((raddr&0x0000FF00)>> 8), 
                                                          ((raddr&0x000000FF)>> 0), 
                                                          rport, ibuf);

        if(sendto(fd, ibuf, len, raddr, rport) < 0){
            printf("[UDP Echo Server] send error \n");
            exit(1);
        }
    }

    exit(0);

    err_usage:
        printf("Usage: udp <port number, 1024-65535> \n");    
        exit(1);
}