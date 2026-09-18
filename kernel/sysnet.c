//
// network system calls.
//

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

struct sock {
  struct sock *next; // the next socket in the list
  uint32 raddr;      // the remote IPv4 address
  uint16 lport;      // the local UDP port number
  uint16 rport;      // the remote UDP port number
  struct spinlock lock; // protects the rxq
  struct mbufq rxq;  // a queue of packets waiting to be received
  uint8  protocol;   // prototype code, same as it is in IP headers, defined in net.h
  uint16 icmp_id;    // unique id for ICMP socket, connect netstack and socket
};

static struct spinlock lock;
static uint16 global_icmp_id = 1;  // 0: unavailable, 1-65535: available; must be protected by lock
static struct sock *sockets;

#define MAX_ICMP_ID             65535
#define MAX_ICMP_ID_ALLOC_RETRY (NFILE+1)  // after this attempt time, return false
#define MAX_ICMP_ECHO_REQ_PAYLOAD 128

void
sockinit(void)
{
  initlock(&lock, "socktbl");
}

/* this allocator will use lock(socket) to protect global_var ::sock:: and ::global_icmp_id::, 
   Must be called before insert sock into linked list. 
*/
uint16 
icmp_id_alloc(void)
{
  acquire(&lock);

  struct sock *curr;
  int flag_collision, res=0;
  for(int cnt=0; cnt < MAX_ICMP_ID_ALLOC_RETRY; cnt++){

    // find if collision in socket linked list
    flag_collision = 0;
    curr = sockets;
    while(curr){
      if((curr->protocol == IPPROTO_ICMP) && (curr->icmp_id == global_icmp_id)){
        flag_collision = 1;
        break;
      }
      curr = curr->next;
    }

    // modify return value
    if(!flag_collision)
      res = global_icmp_id;
    
    // increase global_icmp_id from 1-MAX_ICMP_ID, skip 0
    if(global_icmp_id == MAX_ICMP_ID)
      global_icmp_id = 1;
    else
      global_icmp_id += 1;

    // if collision, try again; otherwise break and return
    if(flag_collision)
      continue;
    else
      break;
  }

  release(&lock);
  return res;
}

int
sockalloc(struct file **f, uint32 raddr, uint16 lport, uint16 rport, uint8 protocol)
{
  struct sock *si, *pos;

  si = 0;
  *f = 0;
  if ((*f = filealloc()) == 0)
    goto bad;
  if ((si = (struct sock*)kalloc()) == 0)
    goto bad;

  // initialize objects
  si->raddr = raddr;
  si->lport = lport;
  si->rport = rport;
  si->protocol = protocol;
  initlock(&si->lock, "sock");
  if(protocol == IPPROTO_ICMP){
    // try to alloc icmp id
    uint16 x = icmp_id_alloc();
    if (x == 0)
      goto bad;
    si->icmp_id = x;
  }
  mbufq_init(&si->rxq);
  (*f)->type = FD_SOCK;
  (*f)->readable = 1;
  (*f)->writable = 1;
  (*f)->sock = si;

  // add to list of sockets
  acquire(&lock);
  pos = sockets;
  while (pos) {
    if (pos->raddr == raddr &&
        pos->lport == lport &&
	pos->rport == rport) {
      release(&lock);
      goto bad;
    }
    pos = pos->next;
  }
  si->next = sockets;
  sockets = si;
  release(&lock);
  return 0;

bad:
  if (si)
    kfree((char*)si);
  if (*f)
    fileclose(*f);
  return -1;
}

void
sockclose(struct sock *si)
{
  struct sock **pos;
  struct mbuf *m;

  // remove from list of sockets
  acquire(&lock);
  pos = &sockets;
  while (*pos) {
    if (*pos == si){
      *pos = si->next;
      break;
    }
    pos = &(*pos)->next;
  }
  release(&lock);

  // free any pending mbufs
  while (!mbufq_empty(&si->rxq)) {
    m = mbufq_pophead(&si->rxq);
    mbuffree(m);
  }

  kfree((char*)si);
}

int
sockread(struct sock *si, uint64 addr, int n)
{
  struct proc *pr = myproc();
  struct mbuf *m;
  int len;

  acquire(&si->lock);
  uint64 deadline = ticks + 20;  // wait for max 2 seconds
  while (mbufq_empty(&si->rxq) && !pr->killed) {
    if(ticks >= deadline){

      if (si->protocol == IPPROTO_ICMP) {
        struct icmp_msg resp;
        resp.resp_ip = local_ip;
        if (copyout(pr->pagetable, addr, (char *)&resp, sizeof(struct icmp_msg)) == -1) {
          release(&si->lock);
          return -1;
        }
      }
      release(&si->lock);
      return -2;
    }
    // sleep(&si->rxq, &si->lock);
  }
  if (pr->killed) {
    release(&si->lock);
    return -1;
  }
  m = mbufq_pophead(&si->rxq);
  release(&si->lock);
  len = m->len;

  if(si->protocol == IPPROTO_UDP)
  {
    if (len > n)
      len = n;

    if (copyout(pr->pagetable, addr, m->head, len) == -1) {
      mbuffree(m);
      return -1;
    }
    return len;
  } 
  else if(si->protocol == IPPROTO_ICMP) 
  {
    if(n != sizeof(struct icmp_msg)){
      mbuffree(m);
      return -1;
    }
    struct icmp_msg resp;
    if (copyin(pr->pagetable, (char *)&resp, addr, sizeof(struct icmp_msg)) == -1) {
      mbuffree(m);
      return -1;
    }
  
    if (len > resp.payload_len)
      len = resp.payload_len;

    resp.type = 1;
    resp.code = 2;
    resp.payload_len = len;
    resp.seq = 4;
    resp.id = 5;

    
    if (copyout(pr->pagetable, (uint64)(resp.payload), m->head, len) == -1) {
      mbuffree(m);
      return -1;
    }

    struct icmp *icmphdr;
    icmphdr = mbufpushhdr(m, *icmphdr);
    resp.type = icmphdr->type;
    resp.code = icmphdr->code;
    resp.id = ntohs(icmphdr->id);
    resp.seq = ntohs(icmphdr->seq); 

    
    struct ip *iphdr;
    iphdr = mbufpushhdr(m, *iphdr);
    resp.resp_ip = ntohl(iphdr->ip_src);
    resp.resp_ttl = iphdr->ip_ttl;

    if (copyout(pr->pagetable, addr, (char *)&resp, sizeof(struct icmp_msg)) == -1) {
      mbuffree(m);
      return -1;
    }
    return len;
  } 
  else {
    mbuffree(m);
    return -1;
  }

  
  
}

int
sockwrite(struct sock *si, uint64 addr, int n)
{
  struct proc *pr = myproc();
  struct mbuf *m;

  m = mbufalloc(MBUF_DEFAULT_HEADROOM);
  if (!m)
    return -1;
  
  
  if (si->protocol == IPPROTO_UDP){
    char *payload = mbufput(m, n);
    if (copyin(pr->pagetable, payload, addr, n) == -1) {
      mbuffree(m);
      return -1;
    }
    net_tx_udp(m, si->raddr, si->lport, si->rport);
  }
    
  else if (si->protocol == IPPROTO_ICMP){
    if (n != sizeof(struct icmp_msg)){
      mbuffree(m);
      return -1;
    }

    struct icmp_msg msg;
    if (copyin(pr->pagetable, (char *)&msg, addr, n) == -1) {
      mbuffree(m);
      return -1;
    }

    if(msg.payload_len > MAX_ICMP_ECHO_REQ_PAYLOAD){
      mbuffree(m);
      return -1;
    }

    char *payload = mbufput(m, msg.payload_len);
    if (copyin(pr->pagetable, (char *)payload, (uint64)msg.payload, msg.payload_len) == -1) {
      mbuffree(m);
      return -1;
    }

    msg.id = si->icmp_id;
    net_tx_icmp(m, si->raddr, &msg);
  }
    
  return n;
}

// called by protocol handler layer to deliver UDP packets
void
sockrecvudp(struct mbuf *m, uint32 raddr, uint16 lport, uint16 rport)
{
  //
  // Find the socket that handles this mbuf and deliver it, waking
  // any sleeping reader. Free the mbuf if there are no sockets
  // registered to handle it.
  //
  struct sock *si;

  acquire(&lock);
  si = sockets;
  while (si) {
    if (si->raddr == raddr && si->lport == lport && si->rport == rport)
      goto found;
    si = si->next;
  }
  release(&lock);
  mbuffree(m);
  return;

found:
  acquire(&si->lock);
  mbufq_pushtail(&si->rxq, m);
  wakeup(&si->rxq);
  release(&si->lock);
  release(&lock);
}

void
sockrecvicmp(struct mbuf *m, uint32 raddr, uint16 id)
{
  struct sock *si;

  acquire(&lock);
  si = sockets;
  while (si) {
    if (si->protocol == IPPROTO_ICMP && si->icmp_id == id && si->raddr == raddr)
      goto found;
    si = si->next;
  }
  release(&lock);

  mbuffree(m);
  return;

  found:
    acquire(&si->lock);
    mbufq_pushtail(&si->rxq, m);
    wakeup(&si->rxq);
    release(&si->lock);
    release(&lock);
}
