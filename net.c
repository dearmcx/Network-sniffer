#define KBUILD_MODNAME "net"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>


BPF_HISTOGRAM(counter, u64);
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

struct event {

	u32	saddr;
	u32	daddr;
	u16	sport;
	u16	dport;
};

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
        struct iphdr *iph = data + sizeof(*eth);
        
        
        //events.saddr = iph->saddr;
        //events.daddr = iph->daddr;
                
        
        //event.saddr = __u32(iph->saddr);
        //event.daddr = __u32(iph->daddr);

	

        if ((void *)iph + sizeof(*iph) <= data_end)
        {
        
        //bpf_trace_printk("ip %x ",iph->saddr);
        event.saddr = iph->saddr;
        event.daddr = iph->daddr;
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
                event.sport = tcph->dest;
                event.dport = tcph->source;                
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
                event.sport = udph->dest;
                event.dport = udph->source;  
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
    return XDP_PASS;
}

