#include "types.h"
#include "riscv.h"
#include "net.h"
#include "spinlock.h"
#include "arp_table.h"
#include "defs.h"


static struct arp_entry arp_table[ARP_HASH_SLOT_SIZE][ARP_LIST_SIZE];
static struct spinlock arp_lock[ARP_HASH_SLOT_SIZE];


void send_mbufs(struct mbuf * p);
void drop_mbufs(struct mbuf *head);
struct mbuf * detach_arp_entry_mbufs_locked(struct arp_entry *p);
int attach_arp_entry_mbufs(struct arp_entry *p, struct mbuf *m);

void
arp_init(void)
{
    for(int i=0; i<ARP_HASH_SLOT_SIZE; i++){
        initlock(&(arp_lock[i]), "arp_lock");
    }
    memset(arp_table, 0, sizeof(struct arp_entry)*ARP_HASH_SLOT_SIZE*ARP_LIST_SIZE);
}


char
octet2char(uint x)
{
    if (x <= 0x9) {
        return '0' + x;
    } else if (x <= 0xF) {
        return 'A' + (x-10);
    } else {
        return '?';
    }
}


void 
fill_mac_str(char *mac_str, int byte_num, uint8 *mac)
{
    for(int i=0; i<byte_num; i++){
        mac_str[3*i+0] = octet2char((mac[i]&0xF0)>>4);
        mac_str[3*i+1] = octet2char(mac[i]&0x0F);
    }
}


void
debug_show_arp(void)
{
    printf("\n========== ARP TABLE ==========\n");
    printf("SLOT-i  LIST-i \t MAC              \t IP     \t age \t pend_len \t state\n");
    for(int i=0; i<ARP_HASH_SLOT_SIZE; i++){
        for(int j=0; j<ARP_LIST_SIZE; j++){
            struct arp_entry *p = &(arp_table[i][j]);
            if (p && (p->state != ARP_ENTRY_FREE)) {
                printf("%d \t %d \t ", i, j);

                char mac_str[18] = "??:??:??:??:??:??\0";
                fill_mac_str(mac_str, ETHADDR_LEN, p->mac);
                printf("%s \t ", mac_str);

                uint32 ip = p->ip;
                printf("%d.%d.%d.%d \t ", ((ip&0xFF000000)>>24), ((ip&0xFF0000)>>16), ((ip&0xFF00)>>8), ip&0xFF);
                
                printf("%d \t ", ticks - p->tick_entry);

                printf(" %d \t\t ", p->pending_mbuf_len);

                if(p->state == ARP_ENTRY_FREE){printf("%s", "ERROR:free");}
                else if (p->state == ARP_ENTRY_RESOLVED){printf("%s", "aging");}
                else if (p->state == ARP_ENTRY_PENDING){printf("%s", "pending");}
                else {printf("%s", "ERROR:else");}

                printf("\n");
            }
            
        }
    }
    printf("\n===============================\n");
}


/* ip is net-order */
int
hash_ip(uint32 ip)
{   
    uint32 x = ip * GOLDEN_RATIO_32;
    x = x >> (32 - ARP_HASH_SLOT_SIZE_SHIFT);
    return (x) & (ARP_HASH_SLOT_SIZE-1);
}


struct spinlock *
arp_get_lock(uint32 ip)
{
    int slot = hash_ip(ip);
    return &arp_lock[slot];
}


struct arp_entry *
arp_table_search_locked(uint32 ip)
{
    int slot = hash_ip(ip);
    struct arp_entry *p;
    for(int i=0; i<ARP_LIST_SIZE; i++){
        p = &(arp_table[slot][i]);
        if ((p->ip == ip) && (p->state == ARP_ENTRY_PENDING || p->state == ARP_ENTRY_RESOLVED)){
            return p;
        }
    }
    return 0;
}


/* add a RESOLVED/PENDING entry, might update/evict */
struct arp_entry *
arp_table_add_locked(uint32 ip, const uint8 *mac, int type)
{   
    int slot = hash_ip(ip);
    
    /* STEP 0: get arp table info */
    int i_free=-1, i_identical=-1;  // first free position, first identical position
    struct arp_entry *p;

    for (int i=0; i<ARP_LIST_SIZE; i++){
        p = &(arp_table[slot][i]);
        if(p->state == ARP_ENTRY_FREE) {
            if (i_free == -1) i_free = i;
        } else if(p->ip == ip) {
            i_identical = i;
        }
    }
    

    /* CASE 1: if find the same IP (PENDING/RESOLVED) */
    if (i_identical >= 0) {
        p = &(arp_table[slot][i_identical]);
        
        /* CASE 1.1: RESOLVED, add RESOLVED: Update info */
        if(p->state == ARP_ENTRY_RESOLVED && type == ARP_ENTRY_RESOLVED) {
            memmove(p->mac, mac, ETHADDR_LEN);
            p->tick_entry = ticks;
            return p;
        }
        
        /* CASE 1.2: RESOLVED, add PENDING: entry expired, replace */
        else if(p->state == ARP_ENTRY_RESOLVED && type == ARP_ENTRY_PENDING) {
            memset(p->mac, 0, ETHADDR_LEN);
            p->tick_entry = 0;
            p->state = ARP_ENTRY_PENDING;
            p->pending_mbuf_head = 0;
            p->pending_mbuf_tail = 0;
            p->pending_mbuf_len = 0;
            p->tick_arp_req = 0;
            return p;
        }

        /* CASE 1.3: PENDING, add PENDING: Update info. 
                     If ARP Request expired, tx again. */
        else if(p->state == ARP_ENTRY_PENDING && type == ARP_ENTRY_PENDING) {
            // now the caller should update tick_arp_req and re-transmit ARP request. 
            // if (ticks - p->tick_arp_req > ARP_REQ_TIMEOUT) {
            //     p->tick_arp_req = ticks;
            // }
            return p;
        }

        /* CASE 1.4: PENDING, add RESOLVED: replace */
        else if(p->state == ARP_ENTRY_PENDING && type == ARP_ENTRY_RESOLVED) {
            memmove(p->mac, mac, ETHADDR_LEN);
            p->tick_entry = ticks;
            p->state = ARP_ENTRY_RESOLVED;
            struct mbuf *detached_head = detach_arp_entry_mbufs_locked(p);
            send_detached_mbufs(detached_head, mac);
            return p;
        }

        /* CASE 1.5: panic */
        else {
            printf("<ERROR><ARP_ADD><branch::found_identical_ip>curr entry state: %d, add state: %d\n", p->state, type);
            return 0;
        }
    }


    /* CASE 2 (evict) : no same ip, add new entry later. 
               If there is no place for new entry (i_free == -1), evict one. */
    int i_evict = -1;
    uint tick_evict = 0xFFFFFFFF;
    if (i_free == -1) {

        // CASE 2.1: find min tick in RESOLVED
        for(int i=0; i<ARP_LIST_SIZE; i++){
            p = &(arp_table[slot][i]);
            if(p->state == ARP_ENTRY_RESOLVED) {
                if(p->tick_entry < tick_evict) {
                    tick_evict = p->tick_entry;
                    i_evict = i;
                }
            }
        }

        // CASE 2.2: no RESOLVED entry, find min tick in PENDING
        if(i_evict == -1) {
            for(int i=0; i<ARP_LIST_SIZE; i++){
                p = &(arp_table[slot][i]);
                if(p->state == ARP_ENTRY_PENDING) {
                    if(p->tick_arp_req < tick_evict) {
                        tick_evict = p->tick_arp_req;
                        i_evict = i;
                    }
                }
            }
        }

        // CASE 2.3: should find a i_evict, evict now; if entry is PENDING, free mbufs
        if(i_evict == -1){
            panic("ARP TABLE ERROR (failed to find evict position)");
        }
        p = &(arp_table[slot][i_evict]);
        struct mbuf *detached_head = detach_arp_entry_mbufs_locked(p);
        printf("[arp table][evict] evict ip %d.%d.%d.%d\n", ((p->ip&0xFF000000)>>24), ((p->ip&0xFF0000)>>16), ((p->ip&0xFF00)>>8), ((p->ip&0xFF)>>0));
        drop_mbufs(detached_head);
        memset(p, 0, sizeof(struct arp_entry));
        i_free = i_evict;
    }

    /* CASE 3: have a free place now, add */
    if (i_free < 0) {
        panic("ARP TABLE ERROR (failed to find free position)");
    }
    p = &(arp_table[slot][i_free]);
    p->ip = ip;
    memmove(p->mac, mac, ETHADDR_LEN);
    if(type == ARP_ENTRY_PENDING){
        p->state = ARP_ENTRY_PENDING;
    } else if (type == ARP_ENTRY_RESOLVED) {
        p->state = ARP_ENTRY_RESOLVED;
        p->tick_entry = ticks;
    }
    return p;
}


/* detach mbuf head/tail/len, free/send them later. */
struct mbuf *
detach_arp_entry_mbufs_locked(struct arp_entry *p)
{
    struct mbuf *res = p->pending_mbuf_head;
    p->pending_mbuf_head = 0;
    p->pending_mbuf_tail = 0;
    p->pending_mbuf_len = 0;
    return res;
}


/* attach a mbuf to pending list. If list reach limit, drop it and return error */
int
attach_arp_entry_mbufs_locked(struct arp_entry *p, struct mbuf *m)
{
    if(p->pending_mbuf_len >= ARP_PENDING_SIZE){
        mbuffree(m);
        return 1;
    }
        
    p->pending_mbuf_len += 1;
    m->next = 0;
    if(p->pending_mbuf_head){
      p->pending_mbuf_tail->next = m;
      p->pending_mbuf_tail = m;
    } else {
      p->pending_mbuf_head = m;
      p->pending_mbuf_tail = m;
    }
    return 0;
}


void
send_detached_mbufs(struct mbuf *head, const uint8 *dmac)
{
    struct mbuf *curr;
    struct eth *ethhdr;

    while(head){
      curr = head;
      head = head->next;
      curr->next = 0;
      
      ethhdr = (struct eth *)curr->head;
      memmove(ethhdr->dhost, dmac, ETHADDR_LEN);
      if (e1000_transmit(curr)) {
        mbuffree(curr);
      }
    }
}

void
drop_mbufs(struct mbuf *head)
{   
    int cnt = 0;
    struct mbuf *curr;
    while(head){
        curr = head;
        head = head->next;
        curr->next = 0;
        mbuffree(curr);
        cnt += 1;
    }
    printf("[drop mbufs] free %d mbufs\n", cnt);
}


uint64
sys_arp_show(void)
{
  debug_show_arp();
  return 0;
}


uint64
sys_arp_add(void)
{
  int ip;       argint(0, &ip);
  uint64 mac_c; argaddr(1, &mac_c);
  
  uint8 mac[ETHADDR_LEN];
  mac[0] = (mac_c >> 40) & 0xFF;
  mac[1] = (mac_c >> 32) & 0xFF;
  mac[2] = (mac_c >> 24) & 0xFF;
  mac[3] = (mac_c >> 16) & 0xFF;
  mac[4] = (mac_c >> 8 ) & 0xFF;
  mac[5] = (mac_c >> 0 ) & 0xFF;

  struct spinlock *lock = arp_get_lock(ip);
  acquire(lock);
  struct arp_entry *p = arp_table_add_locked((uint)ip, mac, ARP_ENTRY_RESOLVED);
  release(lock);
  return p == 0;
}


uint64
sys_arp_autofill(void)
{
    uint ip_base = 0xC0A80A01;
    uint64 mac_base = 0x98AB67000001;
    int limit = ARP_HASH_SLOT_SIZE*ARP_LIST_SIZE;

    struct spinlock *lock;

    for(int i=0; i<limit; i++){
        uint8 mac[ETHADDR_LEN];
        mac[0] = ((mac_base+i) >> 40) & 0xFF;
        mac[1] = ((mac_base+i) >> 32) & 0xFF;
        mac[2] = ((mac_base+i) >> 24) & 0xFF;
        mac[3] = ((mac_base+i) >> 16) & 0xFF;
        mac[4] = ((mac_base+i) >> 8 ) & 0xFF;
        mac[5] = ((mac_base+i) >> 0 ) & 0xFF;

        lock = arp_get_lock(ip_base+i);
        acquire(lock);
        struct arp_entry *p = arp_table_add_locked((uint)(ip_base+i), mac, ARP_ENTRY_RESOLVED);
        release(lock);

        if (p==0){
            printf("[SYS_ARP_AUTOFILL] add error \n");
            return 1;
        }
    }
    return 0;
}
