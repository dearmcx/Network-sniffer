from bcc import BPF #1
from bcc.utils import printb
import time
import struct
import socket
import ctypes as ct

dist ={6:"tcp",17:"udp",1:"icmp",0x806:"arp"}
b = BPF(src_file="net.c") #3
fn = b.load_func("net_filter", BPF.XDP) #4


b.attach_xdp("ens33", fn, 0) #5


net_fter = b["filter"]
net_fter[0] =  ct.c_uint(3232287930)

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    if event.h_proto == 6 or event.h_proto == 17:
    	print("proto: %s saddr: %s sport: %d daddr: %s dport: %d %d" % (dist[event.h_proto],socket.inet_ntoa(struct.pack('I',socket.htonl(event.saddr))) , event.sport,socket.inet_ntoa(struct.pack('I',socket.htonl(event.daddr))),event.dport,event.daddr))
    if event.h_proto == 1:
    	print("proto: %s saddr: %s  daddr: %s " % (dist[event.h_proto],socket.inet_ntoa(struct.pack('I',socket.htonl(event.saddr))) , socket.inet_ntoa(struct.pack('I',socket.htonl(event.daddr)))))
    if event.h_proto == 2054:
    	print("proto: %s " % (dist[event.h_proto]))
	#print(event.ar_sip)
b['buffer'].open_ring_buffer(callback)


try:
    while 1:
        #b.ring_buffer_poll()
        b.trace_print()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()

b.remove_xdp("ens33", 0) #11


