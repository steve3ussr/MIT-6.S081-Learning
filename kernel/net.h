//
// packet buffer management
//

#define MBUF_SIZE              2048
#define MBUF_DEFAULT_HEADROOM  128

#define MBUFQ_TCP_TX_LIMIT_MAX 64000  // limit sum(TCP payload bytes) in mbufq, not mbuf counts

struct mbuf {
  struct mbuf  *next; // the next mbuf in the chain
  char         *head; // the current start position of the buffer
  unsigned int len;   // the length of the buffer
  char         buf[MBUF_SIZE]; // the backing store
  uint16       tcp_payload;   // the length of tcp payload
  uint8        tcp_seq_nxt;   // =tcp_seq if this packet take 0 seq; >tcp_seq for SYN/FIN/payload
  uint32       tcp_seq;
  uint32       tcp_ack;
  uint16       tcp_flags;     // override tcp flags
  struct sock *tcp_socket;
};

char *mbufpull(struct mbuf *m, unsigned int len);
char *mbufpush(struct mbuf *m, unsigned int len);
char *mbufput(struct mbuf *m, unsigned int len);
char *mbuftrim(struct mbuf *m, unsigned int len);

// The above functions manipulate the size and position of the buffer:
//            <- push            <- trim
//             -> pull            -> put
// [-headroom-][------buffer------][-tailroom-]
// |----------------MBUF_SIZE-----------------|
//
// These marcos automatically typecast and determine the size of header structs.
// In most situations you should use these instead of the raw ops above.
#define mbufpullhdr(mbuf, hdr) (typeof(hdr)*)mbufpull(mbuf, sizeof(hdr))
#define mbufpushhdr(mbuf, hdr) (typeof(hdr)*)mbufpush(mbuf, sizeof(hdr))
#define mbufputhdr(mbuf, hdr) (typeof(hdr)*)mbufput(mbuf, sizeof(hdr))
#define mbuftrimhdr(mbuf, hdr) (typeof(hdr)*)mbuftrim(mbuf, sizeof(hdr))

struct mbuf *mbufalloc(unsigned int headroom);
void mbuffree(struct mbuf *m);
extern uint32 local_ip;

struct mbufq {
  struct mbuf *head;  // the first element in the queue
  struct mbuf *tail;  // the last element in the queue
  uint32       len;   // current TCP payload size in total (Include: In-flight data(sent, not ack) + Pending data(not sent))
  uint16       cwnd;  // current window
  uint16       rwnd;  // remote window
  uint32       limit; // queue bytes limitation, len <= limit
};

void mbufq_pushtail(struct mbufq *q, struct mbuf *m);
struct mbuf *mbufq_pophead(struct mbufq *q);
int mbufq_empty(struct mbufq *q);
void mbufq_init(struct mbufq *q);


//
// endianness support
//

static inline uint16 bswaps(uint16 val)
{
  return (((val & 0x00ffU) << 8) |
          ((val & 0xff00U) >> 8));
}

static inline uint32 bswapl(uint32 val)
{
  return (((val & 0x000000ffUL) << 24) |
          ((val & 0x0000ff00UL) << 8) |
          ((val & 0x00ff0000UL) >> 8) |
          ((val & 0xff000000UL) >> 24));
}

// Use these macros to convert network bytes to the native byte order.
// Note that Risc-V uses little endian while network order is big endian.
#define ntohs bswaps
#define ntohl bswapl
#define htons bswaps
#define htonl bswapl


//
// useful networking headers
//

#define ETHADDR_LEN 6

// an Ethernet packet header (start of the packet).
struct eth {
  uint8  dhost[ETHADDR_LEN];
  uint8  shost[ETHADDR_LEN];
  uint16 type;
} __attribute__((packed));

#define ETHTYPE_IP  0x0800 // Internet protocol
#define ETHTYPE_ARP 0x0806 // Address resolution protocol

// an IP packet header (comes after an Ethernet header).
struct ip {
  uint8  ip_vhl; // version << 4 | header length >> 2
  uint8  ip_tos; // type of service
  uint16 ip_len; // total length
  uint16 ip_id;  // identification
  uint16 ip_off; // fragment offset field
  uint8  ip_ttl; // time to live
  uint8  ip_p;   // protocol
  uint16 ip_sum; // checksum
  uint32 ip_src, ip_dst;
};

struct pseudo_ip {
  uint32 ip_src;
  uint32 ip_dst;
  uint8  reserved;
  uint8  ip_p;
  uint16 ip_payload_len;
};

#define IPPROTO_ICMP 1  // Control message protocol
#define IPPROTO_TCP  6  // Transmission control protocol
#define IPPROTO_UDP  17 // User datagram protocol

#define MAKE_IP_ADDR(a, b, c, d)           \
  (((uint32)a << 24) | ((uint32)b << 16) | \
   ((uint32)c << 8) | (uint32)d)

// a UDP packet header (comes after an IP header).
struct udp {
  uint16 sport; // source port
  uint16 dport; // destination port
  uint16 ulen;  // length, including udp header, not including IP header
  uint16 sum;   // checksum
};

// an ICMP message header (comes after an IP header) for KERNEL
struct icmp {
  uint8 type;  // ICMP type
  uint8 code;  // ICMP code
  uint16 sum;  // checksum
  uint16 id;   // TODO: identify client
  uint16 seq;  // TODO: sequence number
};

// an ICMP message for USER
struct icmp_msg {
  uint8  type;         // ICMP type. For Echo Request (ping), type=8, code=0
  uint8  code;         // ICMP code
  uint16 id;           // identifier
  uint16 seq;          // sequence number
  char*  payload;      // payload string
  uint8  payload_len;  // payload string len
  uint32 resp_ip;
  uint32 resp_ttl;
};

// an ARP packet (comes after an Ethernet header).
struct arp {
  uint16 hrd; // format of hardware address
  uint16 pro; // format of protocol address
  uint8  hln; // length of hardware address
  uint8  pln; // length of protocol address
  uint16 op;  // operation

  char   sha[ETHADDR_LEN]; // sender hardware address
  uint32 sip;              // sender IP address
  char   tha[ETHADDR_LEN]; // target hardware address
  uint32 tip;              // target IP address
} __attribute__((packed));

#define ARP_HRD_ETHER 1 // Ethernet

enum {
  ARP_OP_REQUEST = 1, // requests hw addr given protocol addr
  ARP_OP_REPLY = 2,   // replies a hw addr given protocol addr
};

// an DNS packet (comes after an UDP header).
struct dns {
  uint16 id;  // request ID

  uint8 rd: 1;  // recursion desired
  uint8 tc: 1;  // truncated
  uint8 aa: 1;  // authoritive
  uint8 opcode: 4; 
  uint8 qr: 1;  // query/response
  uint8 rcode: 4; // response code
  uint8 cd: 1;  // checking disabled
  uint8 ad: 1;  // authenticated data
  uint8 z:  1;  
  uint8 ra: 1;  // recursion available
  
  uint16 qdcount; // number of question entries
  uint16 ancount; // number of resource records in answer section
  uint16 nscount; // number of NS resource records in authority section
  uint16 arcount; // number of resource records in additional records
} __attribute__((packed));

struct dns_question {
  uint16 qtype;
  uint16 qclass;
} __attribute__((packed));
  
#define ARECORD (0x0001)
#define QCLASS  (0x0001)

struct dns_data {
  uint16 type;
  uint16 class;
  uint32 ttl;
  uint16 len;
} __attribute__((packed));

#define ICMP_TYPE_ECHO_REPLY  0
#define ICMP_TYPE_DST_UNREACH 3
#define ICMP_TYPE_REDIRECT    5
#define ICMP_TYPE_ECHO_REQ    8
#define ICMP_TYPE_RA          9
#define ICMP_TYPE_RS          10
#define ICMP_TYPE_TIME_EXC    11
#define ICMP_TYPE_BAD_PARA    12
#define ICMP_TIMESTAMP        13
#define ICMP_TIMESTAMP_REPLY  14

struct tcp {
  uint16 sport;
  uint16 dport;
  uint32 seq;
  uint32 ack;
  uint16 doff_flags;
  uint16 window;
  uint16 checksum;
  uint16 urg_ptr;
};

#define GET_TCP_FLG(tcphdr)        (ntohs(tcphdr->doff_flags))
#define GET_TCP_HDRLEN(tcphdr)     (((ntohs(tcphdr->doff_flags) & 0xF000) >> 12) << 2)

#define TCP_CWR (1<<7)
#define TCP_ECE (1<<6)
#define TCP_URG (1<<5)
#define TCP_ACK (1<<4)
#define TCP_PSH (1<<3)
#define TCP_RST (1<<2)
#define TCP_SYN (1<<1)
#define TCP_FIN (1<<0)

// TCP Status
#define TCP_STA_CLOSED      0
#define TCP_STA_SYN_SENT    1
#define TCP_STA_EST         2
#define TCP_STA_FIN_WAIT1   3
#define TCP_STA_FIN_WAIT2   4
#define TCP_STA_TIME_WAIT   5

// TCP Events
#define TCP_EVT_USER_OPEN   (1<< 12)
#define TCP_EVT_USER_SEND   (1<< 11)
#define TCP_EVT_USER_CLOSE  (1<< 10)

#define TCP_EVT_RX_DATA     (1<<8)

#define TCP_EVT_RX_ACK      (1<<4)
#define TCP_EVT_RX_PSH      (1<<3)
#define TCP_EVT_RX_RST      (1<<2)
#define TCP_EVT_RX_SYN      (1<<1)
#define TCP_EVT_RX_FIN      (1<<0)

#define TCP_EVT_RETX_TIMEOUT (1<<20)
