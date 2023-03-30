
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <asm/current.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/aio.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/af_unix.h>
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif




BPF_HISTOGRAM(ipv6_counter, u64);
BPF_HISTOGRAM(tcp_counter, u64);
BPF_HISTOGRAM(udp_counter, u64);
BPF_HISTOGRAM(ipv4_counter, u64);
BPF_HISTOGRAM(icmp_counter, u64);
BPF_HISTOGRAM(icmpv6_counter, u64);
BPF_HISTOGRAM(arp_counter, u64);

BPF_RINGBUF_OUTPUT(buffer, 1);
BPF_RINGBUF_OUTPUT(packet, 1);


struct filter
{
    //u8 id;
    //unsigned int enabled : 1;
    //u8 action;
    u32 srcip;
    u32 dstip;
    unsigned int do_sport;
    unsigned int do_dport;
};

struct event {
	u16	h_proto;
	unsigned int	saddr;
	unsigned int	daddr;
	u16	sport;
	u16	dport;
	u32	seq;
	u32	len;
	u32	ack_seq;
	u64 ar_sha;
	u64 ar_tha;
	u32 ar_sip;
	u32 ar_tip;
};


BPF_HASH(filter1,u32 ,struct filter,64);
BPF_PERF_OUTPUT(events);
#define MAX_PKT 512
struct recv_data_t {
    u32 recv_len;
    u8  pkt[MAX_PKT];
};
BPF_PERCPU_ARRAY(unix_data, struct recv_data_t,1);
BPF_PERF_OUTPUT(unix_recv_events);
int net_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct icmp6hdr *icmp6h = NULL;
    unsigned int sip = 0;
    unsigned int dip =0;
    struct event event = {};
    

    if ((void *)eth + sizeof(*eth) <= data_end)
    {
    
     unsigned int len = data_end-data;
     unsigned int new_len ;
     event.len = len;
     bpf_trace_printk("len %d ",len);
	


 

    u32 zero = 0;
    struct recv_data_t *show_data = unix_data.lookup(&zero);
    if (!show_data) {return XDP_PASS;}
    show_data->recv_len = len;
    bpf_probe_read_kernel(&show_data->pkt, len&(MAX_PKT-1), data);

    bpf_trace_printk("nnnnnnnnnn: %x; ",show_data->pkt[3]);
    bpf_trace_printk("nnnnnnnnnk: %x; ",show_data->pkt[8]);    
    unix_recv_events.perf_submit(ctx, show_data, len&(MAX_PKT-1)+sizeof(u32));
    
//unix_recv_events.ringbuf_output(show_data, len&(MAX_PKT-1)+sizeof(u32) , 0);



    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IPV6))
    {
    	struct ipv6hdr *iph6 = NULL;
        struct tcphdr *tcph = NULL;
    	struct udphdr *udph = NULL;
    	struct icmphdr *icmph = NULL;
    	struct icmp6hdr *icmp6h = NULL;
    	ipv6_counter.increment(1);
    	 __uint128_t srcip6 = 0;
        iph6 = (data + sizeof(struct ethhdr));
        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            //return XDP_DROP;
        }
        memcpy(&srcip6, &iph6->saddr.in6_u.u6_addr32, sizeof(srcip6));
        /*
         switch (iph6->nexthdr)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

                // Check TCP header.
                if (tcph + 1 > (struct tcphdr *)data_end)
                {
                    return XDP_DROP;
                }
                tcp_counter.increment(1);

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

                // Check TCP header.
                if (udph + 1 > (struct udphdr *)data_end)
                {
                    return XDP_DROP;
                }
                udp_counter.increment(1);

                break;

            case IPPROTO_ICMPV6:
                // Scan ICMPv6 header.
                icmp6h = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

                // Check ICMPv6 header.
                if (icmp6h + 1 > (struct icmp6hdr *)data_end)
                {
                    return XDP_DROP;
                }
                icmpv6_counter.increment(1);

                break;
        }
        
        */
    }
    else if (eth->h_proto == htons(ETH_P_IP))
    {  
        struct iphdr *iph = data + sizeof(*eth);
        if ((void *)iph + sizeof(*iph) <= data_end)
        {
        ipv4_counter.increment(1);
        bpf_trace_printk("sip %d ",iph->saddr);
        event.h_proto = iph->protocol;
        event.saddr = cpu_to_be32(iph->saddr);
        event.daddr = cpu_to_be32(iph->daddr);
        int key = 0;
  	unsigned int  *val;
  	struct filter *val1;
  	//val = filter.lookup(&key);
  	        int key1 = 0;
  	val1 = filter1.lookup(&key1);
  	/*
  	if (val == NULL) {
  	bpf_trace_printk("NULL1");
        	return XDP_PASS;
    	}*/
  	if (val1 == NULL) {
  	bpf_trace_printk("NULL2");
        	return XDP_DROP;
    	}
  	bpf_trace_printk("filter0: %x ",*val);
  	bpf_trace_printk("filter1 : %x ",event.saddr); 
  	bpf_trace_printk("filter1 : %x ",event.daddr);   	
  	
  	/*
  	if((*val) == event.saddr){
  		return XDP_DROP;
  	}
  	*/
  	bpf_trace_printk("filter2 : %x ",val1->srcip);
  	bpf_trace_printk("filter2 : %x ",val1->dstip);
  	bpf_trace_printk("filter2 : %x ",val1->do_sport);
  	bpf_trace_printk("filter2 : %x ",val1->do_dport);
  	if(val1->srcip == event.saddr){
  		return XDP_DROP;
  	}
  	if(val1->dstip == event.daddr){
  		return XDP_DROP;
  	}  	
  	
        
        
        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check TCP header.
                if (tcph + 1 > (struct tcphdr *)data_end)
                {
                    return XDP_DROP;
                }
                tcp_counter.increment(1);
                event.sport = cpu_to_be16(tcph->dest);
                event.dport = cpu_to_be16(tcph->source);                
		//bpf_trace_printk("tcp %d ",tcph->dest);

		
		
                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check TCP header.
                if (udph + 1 > (struct udphdr *)data_end)
                {
                    return XDP_DROP;
                }
                udp_counter.increment(1);
                event.sport = cpu_to_be16(udph->dest);
                event.dport = cpu_to_be16(udph->source);  
                break;

            case IPPROTO_ICMP:
                // Scan ICMP header.
                icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
		
                // Check ICMP header.
                if (icmph + 1 > (struct icmphdr *)data_end)
                {
                    return XDP_DROP;
                }
		icmp_counter.increment(1);
                break;
        }
         buffer.ringbuf_output(&event, sizeof(event), 0);
       
        /*
            if (ip->protocol == IPPROTO_UDP)
            {

                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end)
                {
                    u64 value = htons(udp->dest);
                    counter.increment(value);
                }
            }
            */
        }
    }
    else if (eth->h_proto == htons(ETH_P_ARP)){
    	struct arphdr *arph = data + sizeof(*eth);
    	if ((void *)arph + sizeof(*arph) <= data_end)
        {
        	arp_counter.increment(1);
    		event.h_proto = cpu_to_be16(eth->h_proto);
    		//memcpy(&event.h_proto,&eth->h_proto,sizeof(event.h_proto));
    		bpf_trace_printk("arp proto: %d ",event.h_proto);
    		int offset = sizeof(arph->ar_hrd) +sizeof(arph->ar_pro) +sizeof(arph->ar_op) +sizeof(arph->ar_hln) +sizeof(arph->ar_pln);
    			buffer.ringbuf_output(&event, sizeof(event), 0);
		
    	}
    
    }
    
    
    
    }
    return XDP_PASS;
}

