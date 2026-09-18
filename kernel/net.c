//
// networking protocol support (IP, UDP, ARP, etc.).
//

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "net.h"
#include "arp_table.h"
#include "defs.h"

uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15); // qemu's idea of the guest IP
static uint32 local_ip_mask = MAKE_IP_ADDR(255, 255, 255, 0);
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
uint8 gateway_mac[ETHADDR_LEN] = { 0x1a, 0x70, 0xfd, 0x73, 0x8e, 0xe9 };
static uint8 broadcast_mac[ETHADDR_LEN] = { 0xFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF };

static int net_tx_arp(uint16 op, uint8 dmac[ETHADDR_LEN], uint32 dip);

// Strips data from the start of the buffer and returns a pointer to it.
// Returns 0 if less than the full requested length is available.
char *
mbufpull(struct mbuf *m, unsigned int len)
{
  char *tmp = m->head;
  if (m->len < len)
    return 0;
  m->len -= len;
  m->head += len;
  return tmp;
}

// Prepends data to the beginning of the buffer and returns a pointer to it.
char *
mbufpush(struct mbuf *m, unsigned int len)
{
  m->head -= len;
  if (m->head < m->buf)
    panic("mbufpush");
  m->len += len;
  return m->head;
}

// Appends data to the end of the buffer and returns a pointer to it.
char *
mbufput(struct mbuf *m, unsigned int len)
{
  char *tmp = m->head + m->len;
  m->len += len;
  if (m->len > MBUF_SIZE)
    panic("mbufput");
  return tmp;
}

// Strips data from the end of the buffer and returns a pointer to it.
// Returns 0 if less than the full requested length is available.
char *
mbuftrim(struct mbuf *m, unsigned int len)
{
  if (len > m->len)
    return 0;
  m->len -= len;
  return m->head + m->len;
}

// Allocates a packet buffer.
struct mbuf *
mbufalloc(unsigned int headroom)
{
  struct mbuf *m;
 
  if (headroom > MBUF_SIZE)
    return 0;
  m = kalloc();
  if (m == 0)
    return 0;
  m->next = 0;
  m->head = (char *)m->buf + headroom;
  m->len = 0;
  memset(m->buf, 0, sizeof(m->buf));
  return m;
}

// Frees a packet buffer.
void
mbuffree(struct mbuf *m)
{
  kfree(m);
}

// Pushes an mbuf to the end of the queue.
void
mbufq_pushtail(struct mbufq *q, struct mbuf *m)
{
  m->next = 0;
  if (!q->head){
    q->head = q->tail = m;
    return;
  }
  q->tail->next = m;
  q->tail = m;
}

// Pops an mbuf from the start of the queue.
struct mbuf *
mbufq_pophead(struct mbufq *q)
{
  struct mbuf *head = q->head;
  if (!head)
    return 0;
  q->head = head->next;
  return head;
}

// Returns one (nonzero) if the queue is empty.
int
mbufq_empty(struct mbufq *q)
{
  return q->head == 0;
}

// Intializes a queue of mbufs.
void
mbufq_init(struct mbufq *q)
{
  q->head = 0;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

// sends an ethernet packet
static void
net_tx_eth(struct mbuf *m, uint16 ethtype)
{
  struct arp_entry *p;
  struct spinlock *lock;
  uint dip;

  struct eth *ethhdr = mbufpushhdr(m, *ethhdr);
  memmove(ethhdr->shost, local_mac, ETHADDR_LEN);
  ethhdr->type = htons(ethtype);
  // In a real networking stack, dhost would be set to the address discovered
  // through ARP. Because we don't support enough of the ARP protocol, set it
  // to broadcast instead.

  if ((ethtype != ETHTYPE_ARP) && (ethtype != ETHTYPE_IP)){
    memmove(ethhdr->dhost, broadcast_mac, ETHADDR_LEN);
    goto send;  // will return in 'send'
  }


  if (ethtype == ETHTYPE_ARP){
    struct arp *arphdr = (struct arp *)(ethhdr + 1);

    if (arphdr->op == htons(ARP_OP_REQUEST)){
      memmove(ethhdr->dhost, broadcast_mac, ETHADDR_LEN);
      goto send;  // will return in 'send'
    }
    else if (arphdr->op == htons(ARP_OP_REPLY)){
      memmove(ethhdr->dhost, arphdr->tha, ETHADDR_LEN);
      goto send;  // will return in 'send'
    }
    else {
      goto drop;  // will return in 'drop'
    }
  } 


  if (ethtype == ETHTYPE_IP) {
    struct ip *iphdr = (struct ip *)(ethhdr + 1);
    dip = ntohl(iphdr->ip_dst);

   // BROADCAST: no need to check arp table
    if (dip == 0xFFFFFFFF)
    {                           
      memmove(ethhdr->dhost, broadcast_mac, ETHADDR_LEN);
      goto send;
    } 
    
    // MULTICAST: no need to check arp table
    else if (((dip & 0xF0000000) >> 28) == 0xE) 
    {   
      ethhdr->dhost[0] = 0x01;
      ethhdr->dhost[1] = 0x00;
      ethhdr->dhost[2] = 0x5E;
      ethhdr->dhost[3] = (dip >> 16) & 0x7F;
      ethhdr->dhost[4] = (dip >> 8)  & 0xFF;
      ethhdr->dhost[5] = dip & 0xFF;
      goto send;
    } 

    // Loopback addr 127.0.0.0/8 : no need to check arp table
    else if (dip == 0 || ((dip & 0xFF000000) == 0x7F000000)) 
    {  
      goto drop;
    } 

    // UNICAST, but not the same subnet
    else if ((dip & local_ip_mask) != (local_ip & local_ip_mask)) {
      memmove(ethhdr->dhost, gateway_mac, ETHADDR_LEN);

      goto send;
    }
    
    // UNICAST
    else {                                          
      lock = arp_get_lock(dip);
      acquire(lock);
      p = arp_table_search_locked(dip);

      if ((p) && (p->state == ARP_ENTRY_PENDING) && (p->pending_mbuf_len >= ARP_PENDING_SIZE)) {
        release(lock);
        goto drop;
      } else if ((p) && (p->state == ARP_ENTRY_RESOLVED) && (ticks - p->tick_entry < ARP_RESOLVE_EXPED)) {
        memmove(ethhdr->dhost, p->mac, ETHADDR_LEN);
        release(lock);
        goto send;
      } else {
        goto pend;  // will modify arp table, release lock and return. 
      }
    }


  } 


  send:
    if (e1000_transmit(m)) {
      mbuffree(m);
    }
    return;

  drop:
    mbuffree(m);
    return;

  pend:  // ARP request, pend, modify entry to pending
    uint8 mac_zero[ETHADDR_LEN] = {0, 0, 0, 0, 0, 0};
    if(!p){
      p = arp_table_add_locked(dip, mac_zero, ARP_ENTRY_PENDING);
    }
    p->tick_entry = 0;
    p->state = ARP_ENTRY_PENDING;
    attach_arp_entry_mbufs_locked(p, m);
    
    int flag_retransmit_arp_request = 0;
    if((ticks - p->tick_arp_req >= ARP_REQ_TIMEOUT) || (p->tick_arp_req == 0)){
      p->tick_arp_req = ticks;
      flag_retransmit_arp_request = 1;
    }
    release(lock);

    if(flag_retransmit_arp_request)
      net_tx_arp(ARP_OP_REQUEST, mac_zero, dip);
    return;
}

// sends an IP packet
static void
net_tx_ip(struct mbuf *m, uint8 proto, uint32 dip)
{
  struct ip *iphdr;

  // push the IP header
  iphdr = mbufpushhdr(m, *iphdr);
  memset(iphdr, 0, sizeof(*iphdr));
  iphdr->ip_vhl = (4 << 4) | (20 >> 2);
  iphdr->ip_p = proto;
  iphdr->ip_src = htonl(local_ip);
  iphdr->ip_dst = htonl(dip);
  iphdr->ip_len = htons(m->len);
  iphdr->ip_ttl = 100;
  iphdr->ip_sum = in_cksum((unsigned char *)iphdr, sizeof(*iphdr));

  // now on to the ethernet layer
  net_tx_eth(m, ETHTYPE_IP);
}

// sends a UDP packet
void
net_tx_udp(struct mbuf *m, uint32 dip,
           uint16 sport, uint16 dport)
{
  struct udp *udphdr;

  // put the UDP header
  udphdr = mbufpushhdr(m, *udphdr);
  udphdr->sport = htons(sport);
  udphdr->dport = htons(dport);
  udphdr->ulen = htons(m->len);
  udphdr->sum = 0; // zero means no checksum is provided

  // now on to the IP layer
  net_tx_ip(m, IPPROTO_UDP, dip);
}

// sends a ICMP packet
void
net_tx_icmp(struct mbuf *m, uint32 dip, struct icmp_msg *msg)
{
  struct icmp *icmphdr = mbufpushhdr(m, *icmphdr);
  icmphdr->type = msg->type;
  icmphdr->code = msg->code;
  icmphdr->id = htons(msg->id);
  icmphdr->seq = htons(msg->seq);
  icmphdr->sum = 0;
  icmphdr->sum = in_cksum((unsigned char *)icmphdr, sizeof(icmphdr)+msg->payload_len);
  net_tx_ip(m, IPPROTO_ICMP, dip);
}

// sends an ARP packet
static int
net_tx_arp(uint16 op, uint8 dmac[ETHADDR_LEN], uint32 dip)
{
  struct mbuf *m;
  struct arp *arphdr;

  m = mbufalloc(MBUF_DEFAULT_HEADROOM);
  if (!m)
    return -1;

  // generic part of ARP header
  arphdr = mbufputhdr(m, *arphdr);
  arphdr->hrd = htons(ARP_HRD_ETHER);
  arphdr->pro = htons(ETHTYPE_IP);
  arphdr->hln = ETHADDR_LEN;
  arphdr->pln = sizeof(uint32);
  arphdr->op = htons(op);

  // ethernet + IP part of ARP header
  memmove(arphdr->sha, local_mac, ETHADDR_LEN);
  arphdr->sip = htonl(local_ip);
  memmove(arphdr->tha, dmac, ETHADDR_LEN);
  arphdr->tip = htonl(dip);

  // header is ready, send the packet
  net_tx_eth(m, ETHTYPE_ARP);
  return 0;
}

// receives an ARP packet
static void
net_rx_arp(struct mbuf *m)
{
  struct arp *arphdr;
  uint8 smac[ETHADDR_LEN];
  uint32 sip, tip;

  arphdr = mbufpullhdr(m, *arphdr);
  if (!arphdr)
    goto done;

  // validate the ARP header
  if (ntohs(arphdr->hrd) != ARP_HRD_ETHER ||
      ntohs(arphdr->pro) != ETHTYPE_IP ||
      arphdr->hln != ETHADDR_LEN ||
      arphdr->pln != sizeof(uint32)) {
    goto done;
  }

  tip = ntohl(arphdr->tip); // target IP address
  sip = ntohl(arphdr->sip); // sender IP address

  // =======  ARP TABLE  =======  
  struct spinlock *lock = arp_get_lock(sip);
  acquire(lock);
  struct arp_entry *p = arp_table_search_locked(sip);
  // CASE 1: add new entry
  if((!p) && (tip == local_ip))
  {           
    p = arp_table_add_locked(sip, (uint8 *)arphdr->sha, ARP_ENTRY_RESOLVED);
    release(lock);
  } 
  // CASE 2: ignore
  else if ((!p) && (tip != local_ip)) 
  {  
    release(lock);
    goto done;
  } 
  // CASE 3: change state PENDING -> RESOLVED, send pending mbufs if possible 
  else if(p->state == ARP_ENTRY_PENDING)
  {
    p->state = ARP_ENTRY_RESOLVED;
    p->tick_entry = ticks;
    memmove(p->mac, arphdr->sha, ETHADDR_LEN);
    
    struct mbuf *head = detach_arp_entry_mbufs_locked(p);
    send_detached_mbufs(head, (uint8 *)arphdr->sha);
    release(lock);
  } 
  // CASE 4: update tick
  else if(p->state == ARP_ENTRY_RESOLVED)
  {
    p->tick_entry = ticks;
    memmove(p->mac, arphdr->sha, ETHADDR_LEN);
    release(lock);
  } 
  // CASE OTHERS: that seems impossible, but goto done whatever. 
  else {
    release(lock);
    goto done;
  }

  if ((ntohs(arphdr->op) == ARP_OP_REQUEST) && (tip == local_ip)){
    // handle the ARP request
    memmove(smac, arphdr->sha, ETHADDR_LEN); // sender's ethernet address
    net_tx_arp(ARP_OP_REPLY, smac, sip);
  }
  goto done;

done:
  mbuffree(m);
}

// receives an ICMP message
static void
net_rx_icmp(struct mbuf *m, uint16 len, struct ip *iphdr)
{
  struct icmp *icmphdr;
  icmphdr = mbufpullhdr(m, *icmphdr);
  if (!icmphdr)
    goto fail;

  // TODO: validate ICMP checksum

  // minimum packet size could be larger than the payload
  mbuftrim(m, m->len - len);
  sockrecvicmp(m, ntohl(iphdr->ip_src), ntohs(icmphdr->id));
  return;

  fail:
    mbuffree(m);
}

// receives a UDP packet
static void
net_rx_udp(struct mbuf *m, uint16 len, struct ip *iphdr)
{
  struct udp *udphdr;
  uint32 sip;
  uint16 sport, dport;


  udphdr = mbufpullhdr(m, *udphdr);
  if (!udphdr)
    goto fail;

  // TODO: validate UDP checksum

  // validate lengths reported in headers
  if (ntohs(udphdr->ulen) != len)
    goto fail;
  len -= sizeof(*udphdr);
  if (len > m->len)
    goto fail;
  // minimum packet size could be larger than the payload
  mbuftrim(m, m->len - len);

  // parse the necessary fields
  sip = ntohl(iphdr->ip_src);
  sport = ntohs(udphdr->sport);
  dport = ntohs(udphdr->dport);
  sockrecvudp(m, sip, dport, sport);
  return;

fail:
  mbuffree(m);
}

// receives an IP packet
static void
net_rx_ip(struct mbuf *m)
{
  struct ip *iphdr;
  uint16 len;

  iphdr = mbufpullhdr(m, *iphdr);
  if (!iphdr)
	  goto fail;

  // check IP version and header len
  if (iphdr->ip_vhl != ((4 << 4) | (20 >> 2)))
    goto fail;
  // validate IP checksum
  if (in_cksum((unsigned char *)iphdr, sizeof(*iphdr)))
    goto fail;
  // can't support fragmented IP packets
  if (htons(iphdr->ip_off) != 0 && htons(iphdr->ip_off) != 0x4000)  // add support to real world
    goto fail;
  // is the packet addressed to us?
  if (htonl(iphdr->ip_dst) != local_ip)
    goto fail;

  len = ntohs(iphdr->ip_len) - sizeof(*iphdr);
  // can only support several protocols
  if (iphdr->ip_p == IPPROTO_UDP) {
    net_rx_udp(m, len, iphdr);
    return;
  } else if (iphdr->ip_p == IPPROTO_ICMP) {
    net_rx_icmp(m, len, iphdr);
    return;
  }
  else {
    goto fail;
  }

  

fail:
  mbuffree(m);
}

// called by e1000 driver's interrupt handler to deliver a packet to the
// networking stack
void net_rx(struct mbuf *m)
{
  struct eth *ethhdr;
  uint16 type;

  ethhdr = mbufpullhdr(m, *ethhdr);
  if (!ethhdr) {
    mbuffree(m);
    return;
  }

  type = ntohs(ethhdr->type);
  if (type == ETHTYPE_IP)
    net_rx_ip(m);
  else if (type == ETHTYPE_ARP)
    net_rx_arp(m);
  else
    mbuffree(m);
}

// int sim_tx(uint32 dst_ip, uint64 dst_mac);
uint64
sys_sim_tx(void)
{
  uint    dst_ip;  argint (0, (int *)&dst_ip ); 
  uint64  dst_mac; argaddr(1, &dst_mac);

  struct mbuf *m = mbufalloc(MBUF_DEFAULT_HEADROOM);

  struct ip *iphdr = mbufpushhdr(m, *iphdr);
  memset(iphdr, 0, sizeof(*iphdr));
  iphdr->ip_vhl = (4 << 4) | (20 >> 2);
  iphdr->ip_p = IPPROTO_UDP;
  iphdr->ip_src = htonl(local_ip);
  iphdr->ip_dst = htonl(dst_ip);
  iphdr->ip_len = htons(m->len);
  iphdr->ip_ttl = 100;
  iphdr->ip_sum = in_cksum((unsigned char *)iphdr, sizeof(*iphdr));

  net_tx_eth(m, ETHTYPE_IP);
  return 0;
}


uint64
sys_sim_rx(void)
{
  uint    dst_ip;  argint (0, (int *)&dst_ip ); 
  uint64  dst_mac; argaddr(1, &dst_mac);
  uint    src_ip;  argint (2, (int *)&src_ip );
  uint64  src_mac; argaddr(3, &src_mac);

  struct mbuf *m = mbufalloc(MBUF_DEFAULT_HEADROOM);

  struct eth *ethhdr = mbufpushhdr(m, *ethhdr);
  memset(ethhdr, 0, sizeof(*ethhdr));
  ethhdr->dhost[0] = (dst_mac >> 40) & 0xFF;
  ethhdr->dhost[1] = (dst_mac >> 32) & 0xFF;
  ethhdr->dhost[2] = (dst_mac >> 24) & 0xFF;
  ethhdr->dhost[3] = (dst_mac >> 16) & 0xFF;
  ethhdr->dhost[4] = (dst_mac >>  8) & 0xFF;
  ethhdr->dhost[5] = (dst_mac >>  0) & 0xFF;

  ethhdr->shost[0] = (src_mac >> 40) & 0xFF;
  ethhdr->shost[1] = (src_mac >> 32) & 0xFF;
  ethhdr->shost[2] = (src_mac >> 24) & 0xFF;
  ethhdr->shost[3] = (src_mac >> 16) & 0xFF;
  ethhdr->shost[4] = (src_mac >>  8) & 0xFF;
  ethhdr->shost[5] = (src_mac >>  0) & 0xFF;
  ethhdr->type = 0x0800;

  
  struct ip *iphdr = mbufpushhdr(m, *iphdr);
  memset(iphdr, 0, sizeof(*iphdr));
  iphdr->ip_vhl = (4 << 4) | (20 >> 2);
  iphdr->ip_p = IPPROTO_UDP;
  iphdr->ip_src = htonl(src_ip);
  iphdr->ip_dst = htonl(dst_ip);
  iphdr->ip_len = m->len;
  iphdr->ip_ttl = 100;
  iphdr->ip_sum = in_cksum((unsigned char *)iphdr, sizeof(*iphdr));
  net_rx_ip(m);
  return 0;
}

uint64
sys_sim_rx_arp_reply(void)
{
  uint    dst_ip;  argint (0, (int *)&dst_ip ); 
  uint64  dst_mac; argaddr(1, &dst_mac);
  uint    src_ip;  argint (2, (int *)&src_ip );
  uint64  src_mac; argaddr(3, &src_mac);

  struct mbuf *m = mbufalloc(MBUF_DEFAULT_HEADROOM);

  struct eth *ethhdr = mbufpushhdr(m, *ethhdr);
  memset(ethhdr, 0, sizeof(*ethhdr));
  ethhdr->dhost[0] = (dst_mac >> 40) & 0xFF;
  ethhdr->dhost[1] = (dst_mac >> 32) & 0xFF;
  ethhdr->dhost[2] = (dst_mac >> 24) & 0xFF;
  ethhdr->dhost[3] = (dst_mac >> 16) & 0xFF;
  ethhdr->dhost[4] = (dst_mac >>  8) & 0xFF;
  ethhdr->dhost[5] = (dst_mac >>  0) & 0xFF;

  ethhdr->shost[0] = (src_mac >> 40) & 0xFF;
  ethhdr->shost[1] = (src_mac >> 32) & 0xFF;
  ethhdr->shost[2] = (src_mac >> 24) & 0xFF;
  ethhdr->shost[3] = (src_mac >> 16) & 0xFF;
  ethhdr->shost[4] = (src_mac >>  8) & 0xFF;
  ethhdr->shost[5] = (src_mac >>  0) & 0xFF;
  ethhdr->type = 0x0800;

  
  struct arp *arphdr = mbufpushhdr(m, *arphdr);
  memset(arphdr, 0, sizeof(*arphdr));
  /*
  struct arp {
    char   sha[ETHADDR_LEN]; // sender hardware address
    uint32 sip;              // sender IP address
    char   tha[ETHADDR_LEN]; // target hardware address
    uint32 tip;              // target IP address
  }
  */
  arphdr->hrd = htons(ARP_HRD_ETHER);
  arphdr->pro = htons(ETHTYPE_IP);
  arphdr->hln = ETHADDR_LEN;
  arphdr->pln = sizeof(uint32);
  arphdr->op = htons(ARP_OP_REPLY);

  // ethernet + IP part of ARP header
  memmove(arphdr->sha, ethhdr->shost, ETHADDR_LEN);
  arphdr->sip = htonl(src_ip);
  memmove(arphdr->tha, ethhdr->dhost, ETHADDR_LEN);
  arphdr->tip = htonl(dst_ip);


  net_rx_arp(m);
  return 0;
}