
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
    u32 srcip;
    u32 dstip;
    unsigned int do_sport;
    unsigned int do_dport;
};


BPF_HASH(filter1,u32 ,struct filter,64);
BPF_PERF_OUTPUT(events);

#define MAX_PKT 2048
struct recv_data_t {
    u8  	pkt[MAX_PKT];
    u32 	recv_len;
    u16 	proto;
    u16	h_proto;
    u16	sport;
    u16	dport;
    unsigned int	saddr;
    unsigned int	daddr;

};
BPF_PERCPU_ARRAY(unix_data, struct recv_data_t,1);
BPF_RINGBUF_OUTPUT(unix_recv_events,16);

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
    
  if ((void *)eth + sizeof(*eth) <= data_end)
  {
    unsigned int len = data_end-data;
    if (eth->h_proto == htons(ETH_P_8021Q) || eth->h_proto == htons(ETH_P_8021AD))
    {
        struct vlan_hdr *vhdr;
        u64 nh_off = sizeof(*eth);
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
        {
            return XDP_DROP;
        }
        return XDP_PASS;
    }
    
    u32 zero = 0;
    struct recv_data_t *show_data = unix_data.lookup(&zero);
    if (!show_data) {return XDP_PASS;}
    show_data->recv_len = len;
    show_data->proto = cpu_to_be16(eth->h_proto);
    if(eth->h_proto == htons(ETH_P_IPV6)||eth->h_proto == htons(ETH_P_IP)||eth->h_proto == htons(ETH_P_ARP)){
    	bpf_probe_read_kernel(&(show_data->pkt), len&(MAX_PKT-1), (u8*)data);
    }

    if (eth->h_proto == htons(ETH_P_IPV6))
    {
    	struct ipv6hdr *iph6 = NULL;
        struct tcphdr *tcph = NULL;
    	struct udphdr *udph = NULL;
    	struct icmphdr *icmph = NULL;
    	struct icmp6hdr *icmp6h = NULL;
    	__uint128_t srcip6 = 0;
    	ipv6_counter.increment(1);
        iph6 = (data + sizeof(struct ethhdr));
        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            return XDP_DROP;
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
         	if (!show_data) {return XDP_PASS;}
        	show_data->h_proto = iph->protocol;
        	show_data->saddr = cpu_to_be32(iph->saddr);
        	show_data->daddr = cpu_to_be32(iph->daddr);

/*
  		int key1 = 0;
  		struct filter *val1;
  		val1 = filter1.lookup(&key1);

         	if (!val1) {return XDP_PASS;}
  		if(val1->srcip == show_data->saddr){
  			return XDP_DROP;
  		}
         	if (!val1) {return XDP_PASS;}  		
  		if(val1->dstip == show_data->daddr){
  			return XDP_DROP;
  		}  	
*/
        	switch (iph->protocol)
        	{
            	case IPPROTO_TCP:
                	tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
                	if (tcph + 1 > (struct tcphdr *)data_end)
                	{
                    		return XDP_DROP;
                	}
                	tcp_counter.increment(1);
                	if (!show_data) {return XDP_PASS;}
                	show_data->sport = cpu_to_be16(tcph->dest);
                	show_data->dport = cpu_to_be16(tcph->source);                
                	break;
            	case IPPROTO_UDP:
                	udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
                	if (udph + 1 > (struct udphdr *)data_end)
                	{
                    		return XDP_DROP;
                	}
                	udp_counter.increment(1);
                	if (!show_data) {return XDP_PASS;}
                	show_data->sport = cpu_to_be16(udph->dest);
                	show_data->dport = cpu_to_be16(udph->source);  
                	break;

            	case IPPROTO_ICMP:
                	icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
                	if (icmph + 1 > (struct icmphdr *)data_end)
               	 {
                    		return XDP_DROP;
                	}
			icmp_counter.increment(1);
                	break;
        	}
         	if (!show_data) {return XDP_PASS;}
           	unix_recv_events.ringbuf_output(show_data, sizeof(*show_data),0);
        }
    }
    else if (eth->h_proto == htons(ETH_P_ARP)){
    	struct arphdr *arph = data + sizeof(*eth);
    	if ((void *)arph + sizeof(*arph) <= data_end)
        {
        	arp_counter.increment(1);
        	if (!show_data) {return XDP_PASS;}
    		show_data->h_proto = cpu_to_be16(eth->h_proto);
    		int offset = sizeof(arph->ar_hrd) +sizeof(arph->ar_pro) +sizeof(arph->ar_op) +sizeof(arph->ar_hln) +sizeof(arph->ar_pln);
		if (!show_data) {return XDP_PASS;}
		unix_recv_events.ringbuf_output(show_data, sizeof(*show_data),0);
    	}
    
    } 
  }
  return XDP_PASS;
}

