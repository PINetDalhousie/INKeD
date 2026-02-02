#ifndef __HELPERS_H
#define __HELPERS_H

#include <stddef.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>

/* Pivot Characteristics */
#ifndef TIME_WINDOW
	#define TIME_WINDOW 5000000000  /* Time window for flow comparison (ns) */
#endif

#ifndef SIZE_WINDOW
	#define SIZE_WINDOW 20000          /* Packet size range to compare (bytes) */
#endif

#ifndef MAX_GROUP_SIZE
	#define MAX_GROUP_SIZE 6        /* Max. size of a flow grouping */
#endif

#ifndef MAX_ENTRIES
	#define MAX_ENTRIES 1024        /* Max. number of flows to store   */
#endif

#define UDP_HDR_LEN 8

/* Flow Structures */
struct flow_id {
    __u32 addr;
    __u32 port;
    __u32 proto;
};

struct flow_entry {
    __u32 srcaddr;
    __u32 dstaddr;
    __u32 srcport;
    __u32 dstport;
    __u32 protocol;
    __u64 start_time;
    __u32 group_idx;
    int f_size;
};

/* Callback Context */
struct ctx {
    struct flow_id* in_id;
    struct flow_entry* curr_entry;
};

struct g_ctx {
    struct flow_entry* group;
    struct flow_entry* curr_entry;
};

/* Packet parsing helpers */
static __always_inline int parse_ethhdr(void**, void*);
static __always_inline int parse_l3(void**, void*, int, struct flow_entry*, struct iphdr**);
static __always_inline int parse_ip4hdr(void**, void*, struct flow_entry*, struct iphdr**);
static __always_inline int parse_l4(void**, void*, int, struct flow_entry*, struct tcphdr**);

/* Flow ID comparison helper */
static __always_inline int compare_flow_addr(struct flow_id*, struct flow_id*);

/* Flow printer */
static __always_inline void print_flow(struct flow_entry*, struct flow_entry*);

/* Callback functions */
static long check_causality(__u32, struct g_ctx*);
static long group_by_time(void*, struct flow_id*, struct flow_entry*, struct ctx*);

#endif
