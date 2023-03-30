from bcc import BPF #1
from bcc.utils import printb
from pylibpcap import OpenPcap
import time
import struct
import socket
import ctypes as ct
import sys
dist ={6:"tcp",17:"udp",1:"icmp",0x806:"arp"}
b = BPF(src_file="net.c") #3
fn = b.load_func("net_filter", BPF.XDP) #4


b.attach_xdp("ens33", fn, 0) #5


#net_fter = b["filter"]
#net_fter[0] =  ct.c_uint(3232287930)

net_fter1 = b["filter1"]
#net_fter1[0] = net_fter1.filter(3232287930,3232287930,443,443)
net_fter1[net_fter1.Key(0)] = net_fter1.Leaf(3232287930,3232287930,443,443)

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    if event.h_proto == 6 or event.h_proto == 17:
    	print("proto: %s saddr: %s sport: %d daddr: %s dport: %d %d" % (dist[event.h_proto],socket.inet_ntoa(struct.pack('I',socket.htonl(event.saddr))) , event.sport,socket.inet_ntoa(struct.pack('I',socket.htonl(event.daddr))),event.dport,event.daddr))
    if event.h_proto == 1:
    	print("proto: %s saddr: %s  daddr: %s " % (dist[event.h_proto],socket.inet_ntoa(struct.pack('I',socket.htonl(event.saddr))) , socket.inet_ntoa(struct.pack('I',socket.htonl(event.daddr)))))
    if event.h_proto == 2054:
    	print("proto: %s " % (dist[event.h_proto]))
	#print(event.ar_sip)
#b['buffer'].open_ring_buffer(callback)

def print_recv_pkg(cpu, data, size):
    event = b["unix_recv_events"].event(data)
    for i in range(0, event.recv_len):
    	print(i)
    for i in range(0, event.recv_len-1):
        print("%02x " % event.pkt[i], end="")
        sys.stdout.flush()
        if (i+1)%16 == 0:
            print("")
            print("----------------", end="")
    print("\n----------------recv %d bytes" % event.recv_len)
   


b["unix_recv_events"].open_perf_buffer(print_recv_pkg)
#b["unix_recv_events"].open_ring_buffer(print_recv_pkg)
#b["events"].open_perf_buffer(cb)
#b['packet'].open_ring_buffer(callback1)

try:
    while 1:
        #b.ring_buffer_poll()
        #b.trace_print()
        b.perf_buffer_poll()
        # or b.ring_buffer_consume()
        #time.sleep(0.5)
except KeyboardInterrupt:
    b.remove_xdp("ens33", 0) 
    sys.exit()
b.remove_xdp("ens33", 0) 
#11


