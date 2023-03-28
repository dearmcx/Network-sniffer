
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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

BPF_HISTOGRAM(counter, u64);
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);


/*
struct filter
{
    //u8 id;
    //unsigned int enabled : 1;
    //u8 action;
    u32 srcip;
    u32 dstip;
    //unsigned int do_sport;
    //unsigned int do_dport;
};
*/



struct event {
	u16	h_proto;
	unsigned int	saddr;
	unsigned int	daddr;
	u16	sport;
	u16	dport;
	u32	seq;
	u32	ack_seq;
	u64 ar_sha;
	u64 ar_tha;
	u32 ar_sip;
	u32 ar_tip;
};

BPF_ARRAY(filter, u32,64);


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
    
    
    if (eth->h_proto == htons(ETH_P_IP))
    {
    
    
        struct iphdr *iph = data + sizeof(*eth);
        
        
        //events.saddr = iph->saddr;
        //events.daddr = iph->daddr;
                
        
        //event.saddr = __u32(iph->saddr);
        //event.daddr = __u32(iph->daddr);

	

        if ((void *)iph + sizeof(*iph) <= data_end)
        {
        
        bpf_trace_printk("sip %d ",iph->saddr);
        event.h_proto = iph->protocol;
        event.saddr = cpu_to_be32(iph->saddr);
        event.daddr = cpu_to_be32(iph->daddr);
        int key = 0;
  	unsigned int  *val;
  	val = filter.lookup(&key);
  	if (val == NULL) {
        	return XDP_PASS;
    	}
  	bpf_trace_printk("filter : %d ",*val);
  	bpf_trace_printk("filter : %x ",event.daddr); 
  	
  	
  	
  	if((*val) == event.saddr){
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
    		event.h_proto = cpu_to_be16(eth->h_proto);
    		//memcpy(&event.h_proto,&eth->h_proto,sizeof(event.h_proto));
    		bpf_trace_printk("arp proto: %d ",event.h_proto);
    		int offset = sizeof(arph->ar_hrd) +sizeof(arph->ar_pro) +sizeof(arph->ar_op) +sizeof(arph->ar_hln) +sizeof(arph->ar_pln);

    		//bpf_trace_printk("sip %x ",cpu_to_be16(&arph->ar_pro));
    		/*
    memcpy(&event.ar_sha, arph+offset, sizeof(event.ar_sha));
    offset += 6;
    // 源协议地址
    memcpy(&event.ar_sip,  arph+offset, sizeof(event.ar_sip));
    offset += 4;
    // 目标硬件地址
    memcpy(&event.ar_tha, arph+offset, sizeof(event.ar_tha));
    offset += 6;
    // 目标协议地址
    memcpy(&event.ar_tip,  arph+offset, sizeof(event.ar_tip));
    */
    buffer.ringbuf_output(&event, sizeof(event), 0);
    

    		//memcpy(&event.ar_sip,&arph->ar_pro,4);
    		//memcpy(&event.ar_tip,&arph->ar_tip,4);   		
    	}
    
    }
    
    
    
    }
    return XDP_PASS;
}

