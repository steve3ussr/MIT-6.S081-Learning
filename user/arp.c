#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/syscall.h"

/* 
    convert string to ip
    instance: "192.168.0.1" -> 0xC0A80001

    return valid ip on success, otherwise return 0
*/
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


/*
    convert string to mac(int)
    instance: "FF:FF:FF:FF:FF:FF" -> 0xFFFFFFFFFFFF

    return valid mac on success, otherwise return 0
*/
uint64 parse_mac(char *s)
{
    /* accept 17 char; 0-9, A-F, a-f only */
    if (strlen(s) != 17) {
        printf("[parse_mac] error mac format\n");
        return 0;
    }

    for(int i=0; i<17; i++){
        char c = s[i];
        if(i%3==2){
            if(c != ':'){
                printf("[parse_mac] error mac format\n");
                return 0;
            }
        } 
        else {
            if (('a' <= c && c <= 'f') || ('A' <= c && c <= 'F') || ('0' <= c && c <= '9')) {}
            else{
                printf("[parse_mac] error mac format\n");
                return 0;
            }
        }
    }  
        
    uint64 res = 0;
    for(int i=0, cnt=0; i<17; i++){
        char c = s[i];
        if (c == ':')
            continue;
        int x = octet2int(c);
        res |= ((uint64)x) << ((11-cnt) << 2);
        cnt++;
    }

    return res;
}



int main(int argc, char **argv){
    if(argc < 2){
        arp_show();
        exit(0);
    }

    char *menu = argv[1];
    if ((strcmp(menu, "add") == 0) || (strcmp(menu, "-a") == 0))
    {
        if(argc != 4)
            goto err_usage;

        char *ip_string = argv[2];
        uint32 ip = parse_ip(ip_string);

        char *mac_string = argv[3];
        uint64 mac = parse_mac(mac_string);
        
        arp_add(ip, mac);
        exit(0);
    } 
    
    else if((strcmp(menu, "autofill") == 0) || (strcmp(menu, "-f") == 0))
        arp_autofill();

    else if((strcmp(menu, "sim-rx-ip") == 0) || (strcmp(menu, "-r") == 0)) {
        if(argc != 6)
            goto err_usage;

        char *dip_string = argv[2];
        uint32 dip = parse_ip(dip_string);

        char *dmac_string = argv[3];
        uint64 dmac = parse_mac(dmac_string);

        char *sip_string = argv[4];
        uint32 sip = parse_ip(sip_string);

        char *smac_string = argv[5];
        uint64 smac = parse_mac(smac_string);
        
        sim_rx(dip, dmac, sip, smac);
        exit(0);
    }

    else if((strcmp(menu, "sim-rx-arp") == 0) || (strcmp(menu, "-R") == 0)) {
        if(argc != 6)
            goto err_usage;

        char *dip_string = argv[2];
        uint32 dip = parse_ip(dip_string);

        char *dmac_string = argv[3];
        uint64 dmac = parse_mac(dmac_string);

        char *sip_string = argv[4];
        uint32 sip = parse_ip(sip_string);

        char *smac_string = argv[5];
        uint64 smac = parse_mac(smac_string);
        
        sim_rx_arp_reply(dip, dmac, sip, smac);
        exit(0);
    }

    else if((strcmp(menu, "sim-tx-ip") == 0) || (strcmp(menu, "-t") == 0)) {
        if(argc != 4)
            goto err_usage;

        char *dip_string = argv[2];
        uint32 dip = parse_ip(dip_string);

        char *dmac_string = argv[3];
        uint64 dmac = parse_mac(dmac_string);

        sim_tx(dip, dmac);
        exit(0);
    }

    else 
        goto err_usage;

    exit(0);

    err_usage:
        printf("Usage: \n");
        printf("  1. add arp entry:       arp add/-a 10.0.2.1 00:00:00:00:00:01 \n");
        printf("  2. show arp table:      arp \n");
        printf("  3. autofill table:      arp autofill/-f \n");
        printf("  4. sim recv ippkt:      arp sim-rx-ip/-r {dip, dmac, sip, smac}\n");
        printf("  5. sim recv arp-reply:  arp sim-rx-arp/-R {dip, dmac, sip, smac}\n");
        printf("  6. sim send ippkt:      arp sim-tx-ip/-t {dip, dmac}\n");
        exit(1);
}