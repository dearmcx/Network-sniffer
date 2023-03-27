from bcc import BPF #1
from bcc.utils import printb
import time

b = BPF(src_file="net.c") #3
fn = b.load_func("net_filter", BPF.XDP) #4
b.attach_xdp("ens33", fn, 0) #5


def callback(ctx, data, size):
    event = b['buffer'].event(data)
    print("saddr:%s sport: %d daddr:%s dport: %d" % (event.saddr, event.sport,event.daddr,event.dport))

b['buffer'].open_ring_buffer(callback)


try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()

b.remove_xdp(device, 0) #11


