#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

#define MSS 1460

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


int append_text(char *payload, int offset, char *s)
{
  int len_s = strlen(s);
  if((offset + len_s) >= MSS){
    printf("[TCP Client] TCP payload overflow \n");
    exit(1);
  }

  for(int i=0; i<len_s; i++){
    payload[offset+i] = s[i];
  }
  return len_s;
}

int append_uint(char *payload, int offset, uint x)
{
  char srev[11] = {'\0'};
  int i=0;

  if(x == 0){
    payload[offset] = '0';
    return 1;
  }

  while(x){
    int x_last = x%10;
    x = x/10;
    srev[i] = x_last + '0';
    i += 1;
  }

  for(int j=0; j<i; j++){
    payload[offset+j] = srev[i-1-j];
  }
  return i;
}

int append_ip(char *payload, int offset, uint ip)
{
    int res=0;
    res += append_uint(payload, offset+res, ((ip>>24) & 0xFF)); res += append_text(payload, offset+res, ".");
    res += append_uint(payload, offset+res, ((ip>>16) & 0xFF)); res += append_text(payload, offset+res, ".");
    res += append_uint(payload, offset+res, ((ip>> 8) & 0xFF)); res += append_text(payload, offset+res, ".");
    res += append_uint(payload, offset+res, ((ip>> 0) & 0xFF));
    return res;
}


int main(int argc, char **argv){
    if(argc != 3 && argc != 1)
        goto err_usage;

    uint32 rhost;
    uint16 rport;

    if(argc == 1){
        rhost = MAKE_IP_ADDR(10, 0, 2, 1);
        rport = 8080;
    } else {
        rhost = parse_ip(argv[1]);
        rport = atoi(argv[2]);
        if(rport == 0)
            goto err_usage;
    }

    int lport = 20000;
    // Step 1: create socket
    int fd;
    if((fd = connect(rhost, lport, rport, IPPROTO_TCP)) < 0){
        fprintf(2, "TCP Client: connect() failed\n");
        exit(1);
    }
    printf("[TCP Client] localhost:%d conn established with %d.%d.%d.%d:%d \n\n",  lport, ((rhost&0xFF000000)>>24), 
                                                          ((rhost&0x00FF0000)>>16), 
                                                          ((rhost&0x0000FF00)>> 8), 
                                                          ((rhost&0x000000FF)>> 0), rport);

    int state = 0;
    nbio(fd, state);

    // Step 2: send HTTP request, GET /
    char payload[MSS+1];
    int offset = 0;
    offset += append_text(payload, offset, "GET / HTTP/1.1\r\n");

    offset += append_text(payload, offset, "Host: ");
    offset += append_ip(payload, offset, rhost);
    offset += append_text(payload, offset, ":");
    offset += append_uint(payload, offset, rport);
    offset += append_text(payload, offset, "\r\n");

    offset += append_text(payload, offset, "Connection: keep-alive\r\n");
    offset += append_text(payload, offset, "Cache-Control: max-age=0\r\n");
    offset += append_text(payload, offset, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36\r\n");
    offset += append_text(payload, offset, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n");
    offset += append_text(payload, offset, "Accept-Encoding: gzip, deflate\r\n");
    offset += append_text(payload, offset, "Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6,zh-HK;q=0.5\r\n");
    offset += append_text(payload, offset, "\r\n");


    printf("n=%d, addr=%p\n", offset, payload);
    if(sendto(fd, payload, offset, 0, 0) < 0){
      printf("[TCP Client] send error \n");
      exit(1);
    }
    printf("[TCP Client] HTTP GET sent. \n");
    sleep(20);


    char *recvbuf = sbrk(10*MSS);
    int len = 0;
    int i = 0;
    int content_length = 0;
    (void)content_length;
    while(1){
        if ((len = recvfrom(fd, recvbuf+i, 10*MSS-i-1, &rhost, &rport)) <= 0){
            printf("--------------------------------------- RECV END -----------------\n");
            break;
        }
        // printf("%s \n", recvbuf+i);
        i += len;
    }
    printf("%s\n", recvbuf);

    printf("[TCP Client] exit now. \n");
    exit(0);

    err_usage:
        printf("Usage: tcp_client RHOST RPORT\n");
        printf("          default 10.0.2.1 8080");    
        exit(1);
}