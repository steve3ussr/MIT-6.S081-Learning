#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"


uint32 parse_ip(char *s)
{
    int n = strlen(s);
    int seg[4]={-1, -1, -1, -1};
    int hi = 0, cnt = 0;

    for(int i=0; i<n; i++){
        char c = s[i];
        if (c == '.' || (('0'<=s[hi]) && (s[hi]<='9'))){
        }
        else{
            printf("[parse_ip] error ip format\n");
            return 0;
        }
    }

    while(hi < n){
        if(cnt >= 4){
            printf("[parse_ip] error ip format\n");
            return 0;
        }

        int tmp = atoi(&(s[hi]));
        if (tmp == 0 && s[hi]!='0')
            break;
        else 
            seg[cnt++] = tmp;
        
        while((hi<n) && ('0'<=s[hi]) && (s[hi]<='9'))
            hi++;
        if(hi<n && s[hi]=='.')
            hi++;
        if(hi<n && s[hi]=='.'){
            printf("[parse_ip] error ip format\n");
            return 0;
        }
    }

    if(cnt != 4){
        printf("[parse_ip] error ip format\n");
        return 0;
    }
    if(seg[0]<0 || seg[0]>255 || seg[1]<0 || seg[1]>255 || seg[2]<0 || seg[2]>255 || seg[3]<0 || seg[3]>255){
        printf("[parse_ip] error ip format\n");
        return 0;
    }


    if(seg[0]==0 && seg[1]==0 && seg[2]==0 && seg[3]==0){
        printf("[parse_ip] warning: invalid ip addr 0.0.0.0 \n");
    }
    uint32 res = (uint32)seg[3] + ((uint32)seg[2]<<8) + ((uint32)seg[1]<<16) + ((uint32)seg[0]<<24);
    return res;
}

int
octet2int(char c)
{
    if ('0' <= c && c <= '9') {
        return c-'0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        printf("octet2int error\n");
        exit(1);
    }
}

char
int2char(int x)
{
    if (0 <= x && x <= 9) {
        return '0' + x-0;
    } else if (0xa <= x && x <= 0xf) {
        return 'a' + x-0xa;
    } else {
        printf("int2char error\n");
        exit(1);
    }
}

int main(int argc, char **argv){
    if(argc < 2){
        goto err_usage;
    }

    uint32 times = 2;  // 2 seconds by default
    uint32 ip;

    if(argc == 2)
    {
        char *ip_string = argv[1];
        ip = parse_ip(ip_string);
        if(ip == 0)
            goto err_usage;
    }

    else if ((argc == 4) && (strcmp(argv[1], "-c") == 0))
    {
        char *ip_string = argv[3];
        ip = parse_ip(ip_string);
        if(ip == 0)
            goto err_usage;

        char *times_string = argv[2];
        times = atoi(times_string);
        if(times == 0)
            goto err_usage; 
    }

    else 
        goto err_usage;


    /* Ping now */
    int fd;
    if((fd = connect(ip, 0, 0, IPPROTO_ICMP)) < 0){
        fprintf(2, "ping: connect() failed\n");
        exit(1);
    }

    struct icmp_msg req;
    req.type = ICMP_TYPE_ECHO_REQ;
    req.code = 0;
    req.payload = "abcdefghijklmnopqrstuvwabcdefghi----xv6";
    req.payload_len = strlen(req.payload);

    // uint64 start, end;

    struct icmp_msg resp;
    char resp_payload[256];

    for(int i=1; i<=4; i++){
        req.seq = i;
        // start = uptime();
        if(write(fd, &req, sizeof(struct icmp_msg)) < 0){
            fprintf(2, "ping: send() failed\n");
            exit(1);
        }

        sleep(10);

        memset(resp_payload, 0, 256);
        memset(&resp, 0, sizeof(struct icmp_msg));
        resp.payload_len = 255;
        resp.payload = resp_payload;

        
        int cc = read(fd, &resp, sizeof(struct icmp_msg));
        if(cc == -1){
            fprintf(2, "ping: recv() failed\n");
            exit(1);
        }

        else if(cc == -2){
            printf("Reply from %d.%d.%d.%d: Destination host unreachable. \n", ((resp.resp_ip&0xFF000000)>>24), 
                                                                 ((resp.resp_ip&0x00FF0000)>>16), 
                                                                 ((resp.resp_ip&0x0000FF00)>> 8), 
                                                                 ((resp.resp_ip&0x000000FF)>> 0));
            continue;
        }

        if (resp.type == ICMP_TYPE_ECHO_REPLY && resp.type == 0){
            // end = uptime();
            printf("Reply from %d.%d.%d.%d: bytes=%d TTL=%d \n", ((resp.resp_ip&0xFF000000)>>24), 
                                                                 ((resp.resp_ip&0x00FF0000)>>16), 
                                                                 ((resp.resp_ip&0x0000FF00)>> 8), 
                                                                 ((resp.resp_ip&0x000000FF)>> 0), 
                                                                 resp.payload_len, 
                                                                 // (end-start),
                                                                 resp.resp_ttl);
        } else if (resp.type == ICMP_TYPE_DST_UNREACH && resp.type == 3) {
            printf("Reply from %d.%d.%d.%d: Destination port unreachable. \n", ((resp.resp_ip&0xFF000000)>>24), 
                                                                               ((resp.resp_ip&0x00FF0000)>>16), 
                                                                               ((resp.resp_ip&0x0000FF00)>> 8), 
                                                                               ((resp.resp_ip&0x000000FF)>> 0));
            continue;
        } else {
            printf("unknown ICMP type. \n");
        }
    }


    exit(0);

    err_usage:
        printf("Usage: \n");
        printf("  ping ip:       ping 10.0.2.2 \n");
        printf("  ping ip x times:       ping -c {x} 10.0.2.2 \n");
        exit(1);
}