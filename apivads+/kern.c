#include "helpers.h"

/* --------------------------------- Maps ---------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_id);
	__type(value, struct flow_entry);
	__uint(max_entries, MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_id);
	__type(value, struct flow_entry [MAX_GROUP_SIZE]);
	__uint(max_entries, MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} groups_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, __u32);
// 	__uint(max_entries, 1);
// 	__uint(pinning, LIBBPF_PIN_BY_NAME);
// } my_ip_map SEC(".maps");

/* ---------------------- Parsing Helper Functions ------------------------- */

static __always_inline int parse_ethhdr(void** pos, void *data_end) 
{
	struct ethhdr *eth = *pos;

	// Bounds checking
	if ((void*)(eth + 1) > data_end)
		return -1;

	// Move header position up
	*pos = eth + 1;

	return eth->h_proto;
}

static __always_inline int parse_l3(void** pos, 
									void* data_end, int nh_type, 
									struct flow_entry* flow_entry,
									struct iphdr** iph)
{
	if (nh_type == bpf_htons(ETH_P_IP))
		nh_type = parse_ip4hdr(pos, data_end, flow_entry, iph);
	else
		return -1;

	return nh_type;
}

static __always_inline int parse_l4(void** pos,
									void* data_end, int nh_type,
									struct flow_entry* flow_entry,
									struct tcphdr** tcph)
{
	if (nh_type == IPPROTO_TCP) {
		struct tcphdr* tcphdr = *pos;
		
		// Bounds checking
		if ((void*)(tcphdr + 1) > data_end)
			return -1;

		flow_entry->srcport = bpf_htons(tcphdr->source);
		flow_entry->dstport = bpf_htons(tcphdr->dest);

		*tcph = tcphdr;

		return IPPROTO_TCP;
	}
	else if (nh_type == IPPROTO_UDP) {
		struct udphdr* udphdr = *pos;

		// Bounds checking
		if ((void*)(udphdr + 1) > data_end)
			return -1;

		flow_entry->srcport = bpf_htons(udphdr->source);
		flow_entry->dstport = bpf_htons(udphdr->dest);

		return IPPROTO_UDP;
	}

	return -1;
}

static __always_inline int parse_ip4hdr(void** pos, void* data_end,
										struct flow_entry* flow_entry,
										struct iphdr** iphdr)
{
	struct iphdr* iph = *pos;
	int hdrlen = 4*iph->ihl;

	// Bounds checking
	if ((void*)(iph + 1) > data_end)
		return -1;
	
	if (*pos + hdrlen > data_end)
		return -1;

	// Store src, dst, and proto
	flow_entry->srcaddr = iph->saddr;
	flow_entry->dstaddr = iph->daddr;
	flow_entry->protocol = iph->protocol;

	// Keep iphdr
	*iphdr = iph;

	// Move header position up
	*pos = iph + 1;

	return iph->protocol;
}

/*--------------------------------- Curr IP -------------------------------- */

// static __always_inline __u32 get_my_ip() {
// 	__u32 key = 0;
// 	__u32* my_ip = bpf_map_lookup_elem(&my_ip_map, &key);
// 	if(my_ip) {
// 		return *(my_ip);
// 	}
// 	else {
// 		return -1;
// 	}
// }


/* --------------------------- Compare Flow IDs ---------------------------- */

static __always_inline int compare_flow_addr(struct flow_id* id1, struct flow_id* id2)
{
	if(id1->addr == id2->addr) {
		return 1;
	}

	return 0;
}


/* ------------------------- Print Flow Information ------------------------ */

static __always_inline void print_flow(struct flow_entry* f_entry_inst, struct flow_entry* f_entry_res) {
	bpf_printk("\nInstigator: "
		"SRC_IP: %lu "
		"DST_IP: %lu "
		"SRC_PORT: %lu "
		"DST_PORT: %lu "
		"SIZE: %lu "
		"START_TIME: %lu "
		"RESULT_SRC: %lu "
		"RESULT_DST: %lu "
		"RESULT_S_PORT: %lu "
		"RESULT_D_PORT: %lu "
		"RESULT_SIZE: %lu "
		"RESULT_STRT_TIME: %lu",
		f_entry_inst->srcaddr, f_entry_inst->dstaddr,
		f_entry_inst->srcport, f_entry_inst->dstport,
		f_entry_inst->f_size,
		f_entry_inst->start_time, f_entry_res->srcaddr,
		f_entry_res->dstaddr, f_entry_res->srcport,
		f_entry_res->dstport,
		f_entry_res->f_size, f_entry_res->start_time);

	return;
}


/* ---------------------------- Group by time ------------------------------ */

static __always_inline int swap(struct flow_entry* a, struct flow_entry* b) {
    struct flow_entry temp = *a;
    *a = *b;
    *b = temp;
	
	return 0;
}

/* Bubble Sort, avoids recursive calls */
static __always_inline int sort_group(struct flow_id* flow) {
	struct flow_entry* group = bpf_map_lookup_elem(&groups_map, flow);
	if(group){
		for (int i=0; i<MAX_GROUP_SIZE - 1; i++) {
			for (int j = 0; j < MAX_GROUP_SIZE - i - 1; j++) {
				if ((group + j)->start_time < (group + j + 1)->start_time)
					swap((group + j), (group + j + 1));
			}
		}

		return 0;
	}
	else {
		return 1;
	}

}

static __always_inline long group_by_time(void* map, struct flow_id* f_id, struct flow_entry* rec_flow, struct ctx* ctx)
{
	struct flow_id* in_id = ctx->in_id;
	struct flow_entry* curr_flow = ctx->curr_entry;

	// Skip flows w/ same src & dst as active flow
	if(compare_flow_addr(in_id, f_id) == 1) {
		return 0;
	}

	// Skip flows that originated in this machine
	// __u32 my_ip = get_my_ip();
	if(rec_flow->srcaddr == 33632778 || rec_flow->srcaddr == 2353245569) {
		return 0;
	}

	/* Recent flow is within TIME_WINDOW before current flow */
	if(rec_flow->start_time > (curr_flow->start_time - TIME_WINDOW) && rec_flow->start_time < curr_flow->start_time) {
		struct flow_entry* group = bpf_map_lookup_elem(&groups_map, in_id);

		if(group) {
			// Cycle through group and replace oldest time
			__u32 oldest_idx = 0;
			__u64 oldest_time = 0;

			for(__u32 idx=0; idx<MAX_GROUP_SIZE; idx++) {
					__u64 curr_time = (group+idx)->start_time;
					//get_start_time((group+idx));

					if(curr_time < oldest_time) {
						oldest_idx = idx;
						oldest_time = curr_time;
					}
			}

			// Replace oldest group entry if curr one is newer
			if(rec_flow->start_time > oldest_time) {
				if(group + oldest_idx < group + MAX_GROUP_SIZE) {
					*(group + oldest_idx) = *(rec_flow);
				}
			}
		}
		
	}

	return 0;	
}


/* ------------------------- Check Flow Causality -------------------------- */

/* Groups are sorted in descending order, thus closest time-match is chosen */
static __always_inline long check_causality(__u32 idx, struct g_ctx* ctx)
{
	struct flow_entry* curr_entry = ctx->curr_entry;
	struct flow_entry* group = ctx->group;

	if(idx >= 0 && idx < MAX_GROUP_SIZE) {
		if(group + idx < group + MAX_GROUP_SIZE) {
			// struct flow_id rec_id = *(group + idx);
			struct flow_entry* rec_flow = (group + idx);
			// bpf_map_lookup_elem(&flow_map, &rec_id);

			if(rec_flow) {
				/* Skip empty entries */
				if(rec_flow->srcaddr == 0) {
					return 0;
				}

				// Skip flows that have not transmitted any data
				if(rec_flow->f_size == 0) {
					return 0;
				}

				if (abs(curr_entry->f_size - rec_flow->f_size) < SIZE_WINDOW) {
					__u32* blocked = bpf_map_lookup_elem(&blocked_ips, &rec_flow->srcaddr);

					/* Don't alert if already blocked */
					if(!blocked) {
						/* Alert Userspace */
						print_flow(rec_flow, curr_entry);

						/* Block Src and Dst */
						// bpf_map_update_elem(&blocked_ips, &rec_flow->srcaddr, &rec_flow->srcaddr, BPF_NOEXIST);
						// bpf_map_update_elem(&blocked_ips, &curr_entry->dstaddr, &curr_entry->dstaddr, BPF_NOEXIST);

						return 1;
					}
				}
			}
		}
	}


	return 0;
}


/* -------------------------- Main --------------------------- */

SEC("tc")
int  spotlight(struct __sk_buff *skb) 
{
	void* data_end = (void *)(long)skb->data_end;
	void* data = (void *)(long)skb->data;
	void* pos = data;
	struct flow_entry flow_entry = {0, 0, 0, 0, 0, 0, 0, 0};
	// __u32 my_ip = get_my_ip();
	__u32 payload_len = 0;
	struct iphdr *iph;
	struct tcphdr *tcph;

	/* Parse Packet */
	int nh_type = parse_ethhdr(&pos, data_end);
	if (nh_type < 0)
		return TC_ACT_SHOT;

	/* Keeping IP hdr */
	nh_type = parse_l3(&pos, data_end, nh_type, &flow_entry, &iph);
	if (nh_type < 0)
		return TC_ACT_OK;

	/* Keeping TCP hdr */
	nh_type = parse_l4(&pos, data_end, nh_type, &flow_entry, &tcph);
	if(nh_type == IPPROTO_TCP) {
		payload_len = bpf_ntohs(iph->tot_len); // - iph->ihl - tcph->doff;
	}
	else if (nh_type == IPPROTO_UDP) {
		payload_len = bpf_ntohs(iph->tot_len); // - iph->ihl - UDP_HDR_LEN;
	}
	else
		return TC_ACT_OK;

	/* Drop blocked packets */
	__u32 src_ip = flow_entry.srcaddr;
	__u32* src = bpf_map_lookup_elem(&blocked_ips, &src_ip);
	if(src){
		return TC_ACT_SHOT;
	}

	__u32 dst_ip = flow_entry.dstaddr;
	__u32* dst = bpf_map_lookup_elem(&blocked_ips, &dst_ip);
	if(dst) {
		return TC_ACT_SHOT;
	}

	/* Find flow ID */
	struct flow_id flow_id = {0, 0, 0};
	flow_id.addr = flow_entry.srcaddr ^ flow_entry.dstaddr;
	flow_id.port = flow_entry.srcport ^ flow_entry.dstport;
	flow_id.proto = flow_entry.protocol;
	
	/* Retrieve Time and Size */
	__u64 pkt_t = bpf_ktime_get_ns();

	/* Store Flow in Hash Map */
	struct flow_entry* f_entry = bpf_map_lookup_elem(&flow_map, &flow_id);

	// Flow exists, update size
	if(f_entry) {
		f_entry->f_size += payload_len;
	}
	// Flow does not exist
	else {
		// Init start time and size
		flow_entry.start_time = pkt_t;
		flow_entry.f_size = payload_len;

		// Create group if flow is outgoing
		if(flow_entry.dstaddr != 2353245569 && flow_entry.dstaddr != 33632778) {

			// Init group if it doesn't exist yet
			struct flow_entry* group = bpf_map_lookup_elem(&groups_map, &flow_id);
			if(!group) {
				struct flow_entry new_group[MAX_GROUP_SIZE] = {0};
				bpf_map_update_elem(&groups_map, &flow_id, &new_group, BPF_ANY);
			}

			struct ctx grouping_ctx = {&flow_id, &flow_entry};
			bpf_for_each_map_elem(&flow_map, group_by_time, &grouping_ctx, 0);
			// sort group
			sort_group(&flow_id);
		}

		// Add new entry
		bpf_map_update_elem(&flow_map, &flow_id, &flow_entry, BPF_NOEXIST);
		f_entry = bpf_map_lookup_elem(&flow_map, &flow_id);
	}

	/* Compare current (outgoing) flow with recent incoming flows in group 
	 * if it has transmitted > 0 bytes */
	if(f_entry && f_entry->dstaddr != 33632778 && f_entry->dstaddr != 2353245569) {
		struct flow_entry* group = bpf_map_lookup_elem(&groups_map, &flow_id);

		if(group && f_entry) {
			struct g_ctx causality_ctx = {group, f_entry};
			bpf_loop(MAX_GROUP_SIZE, check_causality, &causality_ctx, 0);
		}
	}

	return TC_ACT_OK;
}

/* Required in order to use certain bpf helper functions (e.g., bpf_printk) */
char _license[] SEC("license") = "GPL";
