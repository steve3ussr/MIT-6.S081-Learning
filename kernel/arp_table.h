#define ARP_HASH_SLOT_SIZE      16
#define ARP_HASH_SLOT_SIZE_SHIFT 4
#define ARP_LIST_SIZE       4
#define ARP_PENDING_SIZE    10

#define GOLDEN_RATIO_32     0x9E3779B9U

#define ARP_REQ_TIMEOUT     50
#define ARP_RESOLVE_EXPED   600

#define ARP_ENTRY_FREE      0
#define ARP_ENTRY_RESOLVED  1
#define ARP_ENTRY_PENDING   2

struct arp_entry {
    uint32                  ip;
    uint8                   mac[ETHADDR_LEN];
    uint                    tick_entry;
    int                     state;
    struct mbuf *           pending_mbuf_head;
    struct mbuf *           pending_mbuf_tail;
    int                     pending_mbuf_len;
    uint                    tick_arp_req;
};
