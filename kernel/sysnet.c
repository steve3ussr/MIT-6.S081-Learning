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
  struct spinlock lock; // protects the socket
  struct mbufq txq;  // TCP: a queue of TCP packets waiting to be transmitted / acknowledged
  struct mbufq rxq;  // a queue of packets waiting to be received
  uint8  protocol;   // prototype code, same as it is in IP headers, defined in net.h
  uint16 icmp_id;    // unique id for ICMP socket, connect netstack and socket
  uint8  read_blocking;  // 1 (default): block read, 0: non-block read. init with 1, can be set by syscall nbio()
  uint32 snd_una;    // TCP: the first     sent mbuf-tcp-seq in txq, not unacknowledged
  uint32 snd_nxt;    // TCP: the first not-sent mbuf-tcp-seq in txq, awaiting transmit
  uint32 rcv_nxt;    // TCP: the next seq expect received. unequal means loss 
  int    tcp_timer_active;  // TCP: retransmit timer switch
  int    tcp_timer_expire;  // TCP: when ticks >= expire, retransmit
  int    tcp_retx_cnt;      // TCP: retransmit counter
  int    tcp_status;        // TCP: socket status
};

static struct spinlock lock;  // lock for socktbl
static uint16 global_icmp_id = 1;  // 0: unavailable, 1-65535: available; must be protected by lock
static struct sock *sockets;

#define MAX_ICMP_ID             65535
#define MAX_ICMP_ID_ALLOC_RETRY (NFILE+1)  // after this attempt time, return false
#define MAX_ICMP_ECHO_REQ_PAYLOAD 128

#define TCP_SEQ_INIT ticks
#define TCP_MAX_RETX 5    // max retry times. tcp_retx_cnt > 5 will close conn, free socket
#define TCP_RETX_INTV 10  // 10 ticks. Each time retransmit, tcp_retx_cnt++, tcp_timer_expire += INTVL*cnt
#define TCP_MSS      1460

void tcp_txq_enqueue(struct sock *si, struct mbuf *m);
int tcp_sendable(struct sock *si);
int tcp_active_open(struct sock *si);
uint8 tcp_state_trans(struct sock *si, int event);
void tcp_net2sock(struct mbuf *m, struct tcp *tcphdr);
struct mbuf * tcp_active_open_flags(struct sock *si, uint16 flags, int seq_diff, int locked);
void sock_active_close(struct sock *si);


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

// TODO: establish TCP conn
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
  si->read_blocking = 1;
  initlock(&si->lock, "sock");
  if(protocol == IPPROTO_ICMP){
    // try to alloc icmp id
    uint16 x = icmp_id_alloc();
    if (x == 0)
      goto bad;
    si->icmp_id = x;
  } else if (protocol == IPPROTO_TCP) {
    si->snd_nxt = TCP_SEQ_INIT;
    si->snd_una = si->snd_nxt;
    si->rcv_nxt = 0;
    si->tcp_timer_active = 0;
    si->tcp_timer_expire = 0;
    si->tcp_retx_cnt = 0;
    si->tcp_status = TCP_STA_CLOSED;

    // init txq
    mbufq_init(&si->txq);
    si->txq.len = 0;   
    si->txq.cwnd = TCP_MSS;
    si->txq.rwnd = 0xFFFF;
    si->txq.limit = MBUFQ_TCP_TX_LIMIT_MAX;
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

  if(protocol == IPPROTO_TCP){
    int res = tcp_active_open(si);
    if(res < 0){
      sockclose(si);
      printf("[sockalloc] Failed to open TCP Socket\n");
      return -1;
    }
  }
    
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

  // if TCP, send FIN
  printf("[syscall exit - sockclose] triggered. \n");
  if(si->protocol == IPPROTO_TCP)
    sock_active_close(si);

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

  while (!mbufq_empty(&si->txq)) {
    m = mbufq_pophead(&si->txq);
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

  if(si->read_blocking == 1) {
    while (mbufq_empty(&si->rxq) && !pr->killed) {
      sleep(&si->rxq, &si->lock);
    }
  } else if (si->read_blocking == 0) {
    if (mbufq_empty(&si->rxq) && !pr->killed) {
      if (si->protocol == IPPROTO_ICMP) {
        struct icmp_msg resp;
        resp.resp_ip = local_ip;
        if (copyout(pr->pagetable, addr, (char *)&resp, sizeof(struct icmp_msg)) == -1) {
          release(&si->lock);
          return -1;
        }
      }
      release(&si->lock);
      return 0;  // if nothing to read, return 0; copyout local_ip if ICMP
    }
    // else continue to process mbuf
      
  } else {
    release(&si->lock);
    printf("[sockread] sock read blocking method error \n");
    return -1;
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
  else if (si->protocol == IPPROTO_TCP) {
    // step 1: copy payload from user space
    if(n < 0){
      mbuffree(m);
      return -1;
    } else if (n > 0) {
      char *payload = mbufput(m, n);
      if (copyin(pr->pagetable, payload, addr, n) == -1) {
        mbuffree(m);
        printf("[sockwrite][TCP] error at copyin\n");
        return -1;  
      }
    }

    // step 2: fill socket
    m->tcp_socket = si;

    // step 3: get update socket info
    acquire(&si->lock);
    uint32 in_flight = si->snd_nxt - si->snd_una;
    m->tcp_seq = si->snd_nxt;
    m->tcp_payload = n;
    si->snd_nxt += n;

    // add to txq, set timer
    if(!(si->txq.head)){
      si->tcp_timer_active = 1;
      si->tcp_timer_expire = ticks + 1*TCP_RETX_INTV;
      si->tcp_retx_cnt = 0;
    }
    tcp_txq_enqueue(si, m);

    

    int flag_send_now = 0;
    printf("in-flight: %d, cwnd/rwnd=%d, %d\n", in_flight, si->txq.cwnd, si->txq.rwnd);
    if((in_flight <= si->txq.cwnd) && (in_flight <= si->txq.rwnd))
      flag_send_now = 1;
    release(&si->lock);

    if(flag_send_now){
      printf("[sockwrite][TCP] send now!\n");
      tcp_sock2net(m, TCP_EVT_USER_SEND, 0);
    }      
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

void 
sockrecvtcp(struct mbuf *m, uint32 raddr, uint16 lport, uint16 rport, struct tcp *tcphdr)
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
    if (si->raddr == 0 && si->lport == lport && si->rport == 0)
      goto found;
    
    si = si->next;
  }
  release(&lock);
  mbuffree(m);
  return;

  found:
    acquire(&si->lock);
    m->tcp_socket = si;

    tcp_net2sock(m, tcphdr);
    
    wakeup(&si->rxq);
    release(&si->lock);
    release(&lock);

    
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
    // sockrecvudp(m, sip, dport, sport);
    if (si->raddr == 0 && si->lport == lport && si->rport == 0){
      goto found;
    }
      
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

int
sock_set_nbio(struct file *f, int n)
{
  if(f->readable == 0)
    return -1;

  #ifdef LAB_NET
  if(f->type != FD_SOCK)
    return -1;
  printf("[sock_set_nbio] try to set strcu file *f=%p blocking method=%d\n", f, n);
  if(0<=n && n<=1){  // 0: set to non-blocking, 1 (default): set to blocking
    f->sock->read_blocking = n;
    return 0;
  }
  #endif

  return -1;
}

int
sock_recvfrom(struct file *f, uint64 payload, int n, uint64 p_raddr, uint64 p_rport)
{
  
  if(f->readable == 0)
    return -1;
  if(f->type != FD_SOCK)
    return -1;

  struct sock *si = f->sock;
  if(si->protocol != IPPROTO_UDP && si->protocol != IPPROTO_TCP)
    return -1;
  printf("[sock_recvfrom] called. read-blocking=%d\n", si->read_blocking);

  // block/non-block on mbufq
  acquire(&si->lock);
  struct proc *pr = myproc();  
  if(si->read_blocking == 1) {
    while (mbufq_empty(&si->rxq) && !pr->killed) {
      sleep(&si->rxq, &si->lock);
    }
  } else if (si->read_blocking == 0) {
    if (mbufq_empty(&si->rxq) && !pr->killed) {
      release(&si->lock);
      printf("[sock_recvfrom] non-blocking, rxq empty, return 0\n");
      return 0;
    }
    if(!pr->killed){
      release(&si->lock);
      printf("[sock_recvfrom] proc killed\n");
      return 0;
    }
    printf("[sock_recvfrom] non-blocking, rxq head=%p\n", si->rxq.head);
  } else {
    release(&si->lock);
    printf("[sockread] sock read blocking method error \n");
    return -1;
  }

  // make sure pr state OK
  if (pr->killed) {
    release(&si->lock);
    return -1;
  }

  // get mbuf
  struct mbuf *m = mbufq_pophead(&si->rxq);
  release(&si->lock);

  // if mbuf payload length > user want n, trim it. 
  int len = m->len;
  if (len > n)
    len = n;  

  // copyout payload
  if (copyout(pr->pagetable, payload, m->head, len) == -1) {
    mbuffree(m);
    return -1;
  }

  // copyout to p_raddr, p_rport
  struct udp *udphdr = mbufpushhdr(m, *udphdr);
  uint16 rport = ntohs(udphdr->sport);

  struct ip *iphdr = mbufpushhdr(m, *iphdr);
  uint32 raddr = ntohl(iphdr->ip_src);
  if ((copyout(pr->pagetable, p_raddr, (char *)&raddr, sizeof(uint32)) == -1) || (copyout(pr->pagetable, p_rport, (char *)&rport, sizeof(uint16)) == -1)) {
    mbuffree(m);
    return -1;
  }
  return len;
}

int
sock_sendto(struct file *f, uint64 payload, int n, uint32 raddr, uint16 rport)
{
  if(f->readable == 0)
    return -1;
  if(f->type != FD_SOCK)
    return -1;

  struct sock *si = f->sock;
  if(si->protocol != IPPROTO_UDP && si->protocol != IPPROTO_TCP){
    return -1;
  }

  if(si->protocol == IPPROTO_TCP){
    return sockwrite(si, payload, n);
  }

  struct proc *pr = myproc();
  struct mbuf *m = mbufalloc(MBUF_DEFAULT_HEADROOM);
  if (!m)
    return -1;

  // copy payload
  char *mbuf_payload = mbufput(m, n);
  if (copyin(pr->pagetable, mbuf_payload, payload, n) == -1) {
    mbuffree(m);
    return -1;
  }

  if (si->protocol == IPPROTO_UDP){
    net_tx_udp(m, raddr, si->lport, rport);
  } else {
    mbuffree(m);
    return -1;
  }

  
  return 0;
}

// Must be protected by sock.lock
void
tcp_txq_enqueue(struct sock *si, struct mbuf *m)
{
  while(si->txq.len > si->txq.limit){
    sleep(&si->txq, &si->lock);
  }
  mbufq_pushtail(&si->txq, m);
}

int 
tcp_sendable(struct sock *si)
{
  uint32 in_flight = si->snd_nxt - si->snd_una;
  if((in_flight < si->txq.cwnd) && (in_flight < si->txq.rwnd)){
    return 1;
  }
  return 0;
}

int
tcp_sock2net(struct mbuf *m, int event, uint8 flags)
{
  // build a copy
  // mbuf->head should be in the range of [mbuf->buf, mbuf->buf+2048], do not copy that addr
  struct mbuf *mcopy = mbufalloc(MBUF_DEFAULT_HEADROOM);
  if(!mcopy)
    return -1;
  memmove(mcopy, m, sizeof(struct mbuf));
  mcopy->head = (char *)(((uint64)mcopy->buf & (~(PGSIZE-1))) | ((uint64)mcopy->head & (PGSIZE-1)));


  struct sock *si = mcopy->tcp_socket;

  acquire(&si->lock);
  mcopy->tcp_ack = si->rcv_nxt;

  if ((flags != 0)){
    // TODO: override
    tcp_state_trans(si, event);
  } else {
    // let State-Machine decide
    flags = tcp_state_trans(si, event);
    if(flags == 0)
      printf("[TCP sock->net] unknown trans condition: event=%d, curr status=%d \n", event, si->tcp_status);
  }
  release(&si->lock);

  net_tx_tcp(mcopy, si->raddr, si->lport, si->rport, 0xFFFF, flags);
  return 0;
}

// must called with lock(of socket list) and si->lock
void
tcp_net2sock(struct mbuf *m, struct tcp *tcphdr)
{
  struct sock *si = m->tcp_socket;
  // acquire(&si->lock);  // vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv LOCKED
  
  // parse event
  int event = GET_TCP_FLG(tcphdr) & 0xFFF;
  if(m->len > 0)
    event |= TCP_EVT_RX_DATA;

  // parse payload length
  int tcp_payload_length = m->len;

  // update remote seq number
  printf("[TCP_net2sock] event=%d, payload=%d\n", event, tcp_payload_length);
  int seq_diff = 0;
  if(event & TCP_EVT_RX_DATA)
    seq_diff += tcp_payload_length;
  if(event & TCP_EVT_RX_SYN)
    seq_diff += 1;
  if(event & TCP_EVT_RX_FIN)
    seq_diff += 1;
  si->rcv_nxt = ntohl(tcphdr->seq) + seq_diff;

  // update remote wnd
  si->txq.rwnd = ntohs(tcphdr->window);
  
  // trans tcp status, wakeup on chan (active open / close will sleep on that chan) 
  int old_tcp_status = si->tcp_status;
  tcp_state_trans(si, event);
  int new_tcp_status = si->tcp_status; 
  if(new_tcp_status != old_tcp_status)
    wakeup(&si->tcp_status);

  // EST 
  if((new_tcp_status == TCP_STA_EST) && (event & TCP_EVT_RX_DATA)){
    printf("[TCP_net2sock] add a packet(%p) to rxq. \n", ntohs(tcphdr->checksum));
    mbufq_pushtail(&si->rxq, m);

    // TODO: auto response ACK
    struct mbuf *ack = tcp_active_open_flags(si, TCP_ACK, 0, 1);
    if(ack){
      release(&si->lock);
      tcp_sock2net(ack, TCP_EVT_USER_SEND, TCP_ACK);
      acquire(&si->lock);
    }
      
  }
  

  // pophead 
  int flag_popped = 0;
  while((!mbufq_empty(&si->txq))){
    struct mbuf *mhead = si->txq.head;
    printf("[TCP_net2sock] mhead->tcp_seq=%d, nxt=%d; tcphdr->ack=%d\n", mhead->tcp_seq, mhead->tcp_seq_nxt, ntohl(tcphdr->ack));
    if(mhead->tcp_seq_nxt <= ntohl(tcphdr->ack)){  // totoally ack
      flag_popped = 1;
      struct mbuf *tmp = mbufq_pophead(&si->txq);
      mbuffree(tmp);
    } else if(mhead->tcp_seq > ntohl(tcphdr->ack)){  // totally not ack
      printf("[TCP_net2sock] 1 packet not acknowledged. \n");
      break;  // TODO: re-transmit
    } else {  // partrial ack
      printf("[TCP_net2sock] 1 packet partially acknowledged. \n");
            // TODO: modify first packet 
      break; // TODO: re-transmit
    }    
  } 
  
  // if popped: wakeup txq, so maybe some packets can enqueue
  if(flag_popped){
    wakeup(&si->txq);
  }
    
  // if txq size is 0, turn off timer
  if(!(si->txq.head)){
    si->tcp_timer_active = 0;
  } 

  // if popped (at least 1 packet is totally acknowledged), reset timer
  else if(flag_popped){
    si->tcp_timer_active = 1;
    si->tcp_retx_cnt = 0;
    si->tcp_timer_expire = ticks + 1*TCP_RETX_INTV;
  }

  // release(&si->lock);// v^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ RELEASED
}

/* 
  TCP state machine. 
  Must called with protection of si->lock. 
  Auto trans si->tcp_status and return flags.
  return 0: unknown status trans; 
  return True: valid status trans.  
*/
uint8 
tcp_state_trans(struct sock *si, int event)
{
  uint8 flags = 0;
  printf("[tcp_state_trans] event=%d, status %d -> ", event, si->tcp_status);
  if((si->tcp_status == TCP_STA_CLOSED) && (event == TCP_EVT_USER_OPEN)){
    // client主动建立连接 
    flags = TCP_SYN;
    si->tcp_status = TCP_STA_SYN_SENT;
  } 
  else if((si->tcp_status == TCP_STA_SYN_SENT) && (event == (TCP_EVT_RX_SYN | TCP_EVT_RX_ACK))) {
    // client收到SYNACK
    flags = TCP_ACK;
    si->tcp_status = TCP_STA_EST;
  }
  else if((si->tcp_status == TCP_STA_SYN_SENT) && (event != (TCP_EVT_RX_SYN | TCP_EVT_RX_ACK))) {
    flags = TCP_RST;
    si->tcp_status = TCP_STA_FIN_WAIT1;
  }
  else if((si->tcp_status == TCP_STA_EST) && (event == TCP_EVT_USER_OPEN)){
    // client三次握手
    flags = TCP_ACK;
  }
  else if((si->tcp_status == TCP_STA_EST) && (event == TCP_EVT_USER_SEND)){
    // client发送payload
    flags = TCP_ACK | TCP_PSH;
  }
  else if((si->tcp_status == TCP_STA_EST) && (event == (TCP_EVT_RX_ACK | TCP_EVT_RX_DATA))){
    // client收到ACK+DATA
    flags = TCP_ACK;
  }
  else if((si->tcp_status == TCP_STA_EST) && (event == TCP_EVT_USER_CLOSE)){
    // 本机主动关闭
    flags = TCP_FIN;
    si->tcp_status = TCP_STA_FIN_WAIT1;
  }
  else if((si->tcp_status == TCP_STA_FIN_WAIT1) && (event & TCP_EVT_RX_ACK)){
    // 对端回复主动关闭
    si->tcp_status = TCP_STA_FIN_WAIT2;
  }
  else if((si->tcp_status == TCP_STA_FIN_WAIT2) && (event & TCP_EVT_RX_FIN)){
    // 对端主动关闭
    flags = TCP_ACK;
    si->tcp_status = TCP_STA_TIME_WAIT;
  } 
  else if(event & TCP_EVT_RX_RST){
    // 对端重置连接
    si->tcp_status = TCP_STA_CLOSED;
  }
  printf("%d, flags=%d\n", si->tcp_status, flags);
  return flags;
}

// this func will acquire si->lock
struct mbuf *
tcp_active_open_flags(struct sock *si, uint16 flags, int seq_diff, int locked)
{
  struct mbuf *m = mbufalloc(MBUF_DEFAULT_HEADROOM);
  if(!m){
    printf("[tcp_active_open_syn] WARNING: failed to mbufalloc, maybe OOM. \n");
    return 0;
  }

  if(!locked)
    acquire(&si->lock);
  m->tcp_seq = si->snd_nxt;
  m->tcp_seq_nxt = si->snd_nxt+seq_diff;
  m->tcp_payload = 0;
  m->tcp_socket = si;
  m->tcp_flags = flags;
  si->snd_nxt += seq_diff;
  tcp_txq_enqueue(si, m);
  if(!locked)
    release(&si->lock);

  return m;
}

// return 0 : success
// return -1: fail on sending SYN
// return -2: remote RESET connection
// return -3: fail on UNKNOWN
// return -4: fail on sending ACK
int
tcp_active_open(struct sock *si)
{
  // build mbuf syn, add syn to txq, send a copy in tcp_sock2net
  struct mbuf *syn = tcp_active_open_flags(si, TCP_SYN, 1, 0);
  if(!syn)
    return -1;
  tcp_sock2net(syn, TCP_EVT_USER_OPEN, TCP_SYN);  // tcp_sock2net: CLOSED->SENT
      
  // waiting for response
  acquire(&si->lock);
  while((si->tcp_status == TCP_STA_SYN_SENT))  
    sleep(&si->tcp_status, &si->lock);
  printf("[TCP_ACTIVE_OPEN] awaken, status=%d\n", si->tcp_status);
  if(si->tcp_status == TCP_STA_CLOSED){
    release(&si->lock);
    return -2;
  } else if(si->tcp_status != TCP_STA_EST){
    release(&si->lock);
    struct mbuf *rst = tcp_active_open_flags(si, TCP_RST, 0, 0);
    if(rst)
      tcp_sock2net(rst, TCP_EVT_USER_OPEN, TCP_RST); 
    return -3;
  }
  release(&si->lock);
  printf("[TCP_ACTIVE_OPEN] socket EST now. \n");
  // socket->tcp_status == EST now
  
  // send a ACK
  struct mbuf *ack = tcp_active_open_flags(si, TCP_ACK, 0, 0);
  if(!ack)
    return -4;
  tcp_sock2net(ack, TCP_EVT_USER_OPEN, TCP_ACK);

  return 0;
}

void
sock_active_close(struct sock *si)
{
  // build mbuf fin, add syn to txq, send a copy in tcp_sock2net
  struct mbuf *fin = tcp_active_open_flags(si, TCP_FIN | TCP_ACK, 1, 0);
  if(!fin)
    return;
  tcp_sock2net(fin, TCP_EVT_USER_CLOSE, TCP_FIN | TCP_ACK);  // tcp_sock2net: EST->FIN_WAIT1

  // waiting for response ACK
  acquire(&si->lock);
  while((si->tcp_status == TCP_STA_FIN_WAIT1))  
    sleep(&si->tcp_status, &si->lock);
  printf("[TCP_ACTIVE_CLOSE] FIN-ACK-1, status=%d\n", si->tcp_status);
  if(si->tcp_status == TCP_STA_CLOSED){
    release(&si->lock);
    return;
  } else if(si->tcp_status != TCP_STA_FIN_WAIT2){
    release(&si->lock);
    struct mbuf *rst = tcp_active_open_flags(si, TCP_RST, 0, 0);
    if(rst)
      tcp_sock2net(rst, 0, TCP_RST); 
    return;
  }
  release(&si->lock);
  printf("[TCP_ACTIVE_CLOSE] socket FIN_WAIT2 now. \n");
  // socket->tcp_status == EST now

  // waiting for remote FIN
  acquire(&si->lock);
  while((si->tcp_status == TCP_STA_FIN_WAIT2))  
    sleep(&si->tcp_status, &si->lock);
  printf("[TCP_ACTIVE_CLOSE] FIN-2 received, status=%d\n", si->tcp_status);
  if(si->tcp_status == TCP_STA_CLOSED){
    release(&si->lock);
    return;
  } else if(si->tcp_status != TCP_STA_TIME_WAIT){
    release(&si->lock);
    struct mbuf *rst = tcp_active_open_flags(si, TCP_RST, 0, 0);
    if(rst)
      tcp_sock2net(rst, 0, TCP_RST); 
    return;
  }
  release(&si->lock);
  printf("[TCP_ACTIVE_CLOSE] socket FIN-2 received now. \n");

  // send last ACK
  struct mbuf *ack = tcp_active_open_flags(si, TCP_ACK, 1, 0);
  if(!ack)
    return;
  tcp_sock2net(ack, TCP_EVT_USER_CLOSE, TCP_ACK);
  return;
}



// TODO: not implicated
void
sock_retransmit()
{

  // acquire(&lock);

  struct sock *curr = sockets;
  while (curr) {
    

    if (curr->protocol == IPPROTO_TCP &&
        curr->tcp_timer_active == 1 && 
        curr->tcp_timer_expire <= ticks && 
        curr->txq.head) {
      
      // acquire(&curr->lock);  // TODO: deadlock

      curr->tcp_retx_cnt += 1;
      curr->tcp_timer_expire = (1 + curr->tcp_retx_cnt) * TCP_RETX_INTV;

      if(curr->tcp_retx_cnt >= TCP_MAX_RETX){
        // release(&curr->lock);
        // release(&lock);
        sockclose(curr);
        return;
      } else {
        printf("[sock_retransmit] retry %d times on sock %p \n", curr->tcp_retx_cnt, curr);
        tcp_sock2net(curr->txq.head, TCP_EVT_USER_SEND, 0);
      }

      // release(&curr->lock);
    }
    
    
    curr = curr->next;
  }
  // release(&lock);
}