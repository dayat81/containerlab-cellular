/*
 * eBPF Traffic Monitor for 5G UPF
 * 
 * Monitors per-UE traffic on the ogstun interface (user plane)
 * and eth1 interface (GTP-U tunnels) for Open5GS UPF.
 * 
 * Collects: bytes, packets, timestamps per UE IP
 * Parses: GTP-U headers to extract QFI (QoS Flow Identifier)
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* GTP-U header definitions */
#define GTP_UDP_PORT 2152
#define GTP_VERSION_V1 1

/* GTP-U header flags */
#define GTP_FLAG_VERSION_MASK  0xE0
#define GTP_FLAG_PT_MASK       0x10
#define GTP_FLAG_E_MASK        0x04
#define GTP_FLAG_S_MASK        0x02
#define GTP_FLAG_PN_MASK       0x01

/* GTP-U Extension Header Types */
#define GTP_EXT_PDU_SESSION_CONTAINER 0x85

/* Traffic statistics structure */
struct traffic_stats {
    __u64 bytes_in;       /* Bytes received (downlink to UE) */
    __u64 bytes_out;      /* Bytes sent (uplink from UE) */
    __u64 packets_in;     /* Packets received */
    __u64 packets_out;    /* Packets sent */
    __u64 first_seen_ns;  /* First packet timestamp (nanoseconds) */
    __u64 last_seen_ns;   /* Last packet timestamp (nanoseconds) */
    __u8  qfi;            /* QoS Flow Identifier (from GTP-U) */
    __u8  active;         /* Session active flag */
    __u16 padding;
};

/* GTP-U base header (8 bytes) */
struct gtpu_hdr {
    __u8  flags;
    __u8  msg_type;
    __be16 length;
    __be32 teid;
} __attribute__((packed));

/* GTP-U optional header (4 bytes when E, S, or PN flags set) */
struct gtpu_opt_hdr {
    __be16 seq_num;
    __u8   npdu_num;
    __u8   next_ext_type;
} __attribute__((packed));

/* PDU Session Container Extension Header */
struct pdu_session_container {
    __u8  length;       /* Length in 4-byte units */
    __u8  pdu_type_qfi; /* Upper 4 bits: PDU type, Lower 6 bits: QFI */
    __u8  padding;
    __u8  next_ext;
} __attribute__((packed));

/* BPF Map: Per-UE IPv4 traffic statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              /* UE IPv4 address */
    __type(value, struct traffic_stats);
} ue_traffic_stats SEC(".maps");

/* BPF Map: Per-TEID statistics (for GTP-U correlation) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              /* TEID */
    __type(value, struct traffic_stats);
} teid_stats SEC(".maps");

/* BPF Map: Global counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} global_counters SEC(".maps");

#define COUNTER_TOTAL_PACKETS 0
#define COUNTER_TOTAL_BYTES   1
#define COUNTER_GTP_PACKETS   2
#define COUNTER_ERRORS        3

/* Helper: Update global counter */
static __always_inline void update_global_counter(__u32 key, __u64 delta) {
    __u64 *counter = bpf_map_lookup_elem(&global_counters, &key);
    if (counter) {
        __sync_fetch_and_add(counter, delta);
    }
}

/* Helper: Update or create traffic stats for a UE IP */
static __always_inline void update_ue_stats(__u32 ue_ip, __u32 bytes, int is_ingress, __u8 qfi) {
    struct traffic_stats *stats;
    struct traffic_stats new_stats = {0};
    __u64 now = bpf_ktime_get_ns();
    
    stats = bpf_map_lookup_elem(&ue_traffic_stats, &ue_ip);
    
    if (stats) {
        /* Update existing entry */
        if (is_ingress) {
            __sync_fetch_and_add(&stats->bytes_in, bytes);
            __sync_fetch_and_add(&stats->packets_in, 1);
        } else {
            __sync_fetch_and_add(&stats->bytes_out, bytes);
            __sync_fetch_and_add(&stats->packets_out, 1);
        }
        stats->last_seen_ns = now;
        if (qfi > 0) {
            stats->qfi = qfi;
        }
        stats->active = 1;
    } else {
        /* Create new entry */
        new_stats.first_seen_ns = now;
        new_stats.last_seen_ns = now;
        new_stats.qfi = qfi;
        new_stats.active = 1;
        
        if (is_ingress) {
            new_stats.bytes_in = bytes;
            new_stats.packets_in = 1;
        } else {
            new_stats.bytes_out = bytes;
            new_stats.packets_out = 1;
        }
        
        bpf_map_update_elem(&ue_traffic_stats, &ue_ip, &new_stats, BPF_ANY);
    }
}

/* Helper: Parse GTP-U header and extract QFI */
static __always_inline int parse_gtpu(__u8 *data, __u8 *data_end, __u32 *teid, __u8 *qfi, __u32 *inner_offset) {
    struct gtpu_hdr *gtpu;
    struct gtpu_opt_hdr *opt;
    __u32 offset = 0;
    __u8 flags;
    
    /* Parse GTP-U base header */
    gtpu = (struct gtpu_hdr *)data;
    if ((void *)(gtpu + 1) > (void *)data_end)
        return -1;
    
    flags = gtpu->flags;
    *teid = bpf_ntohl(gtpu->teid);
    offset = sizeof(struct gtpu_hdr);
    
    /* Check if optional header present (E, S, or PN flags) */
    if (flags & (GTP_FLAG_E_MASK | GTP_FLAG_S_MASK | GTP_FLAG_PN_MASK)) {
        opt = (struct gtpu_opt_hdr *)(data + offset);
        if ((void *)(opt + 1) > (void *)data_end)
            return -1;
        
        offset += sizeof(struct gtpu_opt_hdr);
        
        /* Parse extension headers if E flag set */
        if (flags & GTP_FLAG_E_MASK) {
            __u8 next_ext = opt->next_ext_type;
            
            /* Look for PDU Session Container */
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                if (next_ext == 0)
                    break;
                
                if (next_ext == GTP_EXT_PDU_SESSION_CONTAINER) {
                    struct pdu_session_container *psc;
                    psc = (struct pdu_session_container *)(data + offset);
                    if ((void *)(psc + 1) > (void *)data_end)
                        return -1;
                    
                    /* Extract QFI from lower 6 bits */
                    *qfi = psc->pdu_type_qfi & 0x3F;
                    next_ext = psc->next_ext;
                    offset += psc->length * 4;
                } else {
                    /* Skip unknown extension */
                    __u8 *ext_len = data + offset;
                    if ((void *)(ext_len + 1) > (void *)data_end)
                        return -1;
                    
                    __u8 len = *ext_len * 4;
                    if (len == 0)
                        break;
                    
                    offset += len;
                    if (offset + 1 > (data_end - data))
                        return -1;
                    
                    next_ext = *(data + offset - 1);
                }
            }
        }
    }
    
    *inner_offset = offset;
    return 0;
}

/*
 * TC classifier for ogstun interface (TUN device)
 * Handles pure IP packets (no Ethernet header)
 * 
 * Ingress: Downlink traffic TO UE (dst = UE IP)
 * Egress: Uplink traffic FROM UE (src = UE IP)
 */
SEC("tc/ogstun_ingress")
int ogstun_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph;
    __u32 ue_ip;
    __u32 pkt_len;
    
    /* Parse IP header (TUN device has no Ethernet header) */
    iph = data;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    /* Only handle IPv4 for now */
    if (iph->version != 4)
        return TC_ACT_OK;
    
    /* Ingress to ogstun = downlink to UE, dst is UE IP */
    ue_ip = iph->daddr;
    pkt_len = bpf_ntohs(iph->tot_len);
    
    /* Update statistics */
    update_ue_stats(ue_ip, pkt_len, 1, 0);
    update_global_counter(COUNTER_TOTAL_PACKETS, 1);
    update_global_counter(COUNTER_TOTAL_BYTES, pkt_len);
    
    return TC_ACT_OK;
}

SEC("tc/ogstun_egress")
int ogstun_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph;
    __u32 ue_ip;
    __u32 pkt_len;
    
    /* Parse IP header */
    iph = data;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    if (iph->version != 4)
        return TC_ACT_OK;
    
    /* Egress from ogstun = uplink from UE, src is UE IP */
    ue_ip = iph->saddr;
    pkt_len = bpf_ntohs(iph->tot_len);
    
    /* Update statistics */
    update_ue_stats(ue_ip, pkt_len, 0, 0);
    update_global_counter(COUNTER_TOTAL_PACKETS, 1);
    update_global_counter(COUNTER_TOTAL_BYTES, pkt_len);
    
    return TC_ACT_OK;
}

/*
 * TC classifier for eth1 interface (GTP-U tunnel interface)
 * Parses GTP-U headers to extract TEID and QFI
 */
SEC("tc/gtpu_ingress")
int gtpu_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth;
    struct iphdr *outer_ip, *inner_ip;
    struct udphdr *udp;
    __u32 teid = 0;
    __u8 qfi = 0;
    __u32 inner_offset = 0;
    __u32 gtpu_start;
    
    /* Parse Ethernet header */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    /* Parse outer IP header */
    outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (outer_ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    /* Parse UDP header */
    udp = (struct udphdr *)((void *)outer_ip + (outer_ip->ihl * 4));
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    /* Check for GTP-U port */
    if (bpf_ntohs(udp->dest) != GTP_UDP_PORT && bpf_ntohs(udp->source) != GTP_UDP_PORT)
        return TC_ACT_OK;
    
    update_global_counter(COUNTER_GTP_PACKETS, 1);
    
    /* Parse GTP-U header */
    gtpu_start = sizeof(*eth) + (outer_ip->ihl * 4) + sizeof(*udp);
    if (gtpu_start > (data_end - data))
        return TC_ACT_OK;
    
    if (parse_gtpu(data + gtpu_start, data_end, &teid, &qfi, &inner_offset) < 0) {
        update_global_counter(COUNTER_ERRORS, 1);
        return TC_ACT_OK;
    }
    
    /* Parse inner IP header */
    __u32 inner_ip_start = gtpu_start + inner_offset;
    if (inner_ip_start + sizeof(struct iphdr) > (data_end - data))
        return TC_ACT_OK;
    
    inner_ip = (struct iphdr *)(data + inner_ip_start);
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (inner_ip->version == 4) {
        /* Ingress GTP-U = downlink, destination is UE */
        __u32 ue_ip = inner_ip->daddr;
        __u32 pkt_len = bpf_ntohs(inner_ip->tot_len);
        
        update_ue_stats(ue_ip, pkt_len, 1, qfi);
    }
    
    return TC_ACT_OK;
}

SEC("tc/gtpu_egress")
int gtpu_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth;
    struct iphdr *outer_ip, *inner_ip;
    struct udphdr *udp;
    __u32 teid = 0;
    __u8 qfi = 0;
    __u32 inner_offset = 0;
    __u32 gtpu_start;
    
    /* Parse Ethernet header */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    /* Parse outer IP header */
    outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (outer_ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    /* Parse UDP header */
    udp = (struct udphdr *)((void *)outer_ip + (outer_ip->ihl * 4));
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    /* Check for GTP-U port */
    if (bpf_ntohs(udp->dest) != GTP_UDP_PORT && bpf_ntohs(udp->source) != GTP_UDP_PORT)
        return TC_ACT_OK;
    
    /* Parse GTP-U header */
    gtpu_start = sizeof(*eth) + (outer_ip->ihl * 4) + sizeof(*udp);
    if (gtpu_start > (data_end - data))
        return TC_ACT_OK;
    
    if (parse_gtpu(data + gtpu_start, data_end, &teid, &qfi, &inner_offset) < 0)
        return TC_ACT_OK;
    
    /* Parse inner IP header */
    __u32 inner_ip_start = gtpu_start + inner_offset;
    if (inner_ip_start + sizeof(struct iphdr) > (data_end - data))
        return TC_ACT_OK;
    
    inner_ip = (struct iphdr *)(data + inner_ip_start);
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (inner_ip->version == 4) {
        /* Egress GTP-U = uplink, source is UE */
        __u32 ue_ip = inner_ip->saddr;
        __u32 pkt_len = bpf_ntohs(inner_ip->tot_len);
        
        update_ue_stats(ue_ip, pkt_len, 0, qfi);
    }
    
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
