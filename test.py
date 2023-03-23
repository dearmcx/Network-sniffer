from bcc import BPF #1
from bcc.utils import printb

device = "lo" #2
b = BPF(src_file="udp_counter.c") #3
fn = b.load_func("udp_counter", BPF.XDP) #4
b.attach_xdp(device, fn, 0) #5
b.attach_xdp("ens33", fn, 0) #5
try:
    b.trace_print() #6
except KeyboardInterrupt: #7

    dist = b.get_table("counter") #8
    print(dist.items())
    #for k, v in sorted(dist.items()): #9
    #	print(k.value)
        #print("DEST_PORT : %, COUNT : %10d" % (k.value, v.value)) #10

b.remove_xdp(device, 0) #11


