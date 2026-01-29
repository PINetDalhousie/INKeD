from bcc import BPF
import socket
from ctypes import *
import pyroute2
from pyroute2 import NetlinkError
import re
import sys

device = 'eno0'
dev2 = "eno1"

print("USING NICs " + device + ", " + dev2)
ipr = pyroute2.IPRoute()
eth = ipr.link_lookup(ifname=device)[0]
eth2 = ipr.link_lookup(ifname=dev2)[0]

try:
    ipr.tc("add", "clsact", eth)
except NetlinkError as e:
    if 'File exists' in str(e):
        pass
    else:
        raise

try:
    ipr.tc("add", "clsact", eth2)
except NetlinkError as e:
    if 'File exists' in str(e):
        pass
    else:
        raise

tw = sys.argv[1]
sw = sys.argv[2] # input in miliseconds
log_dir = sys.argv[3]

b = BPF(src_file="inked.ebpf.c", cflags=[f"-DTIME_NS={tw}000000", f"-DSIZE_B={sw}"])

fn = b.load_func("handle_ingress", BPF.XDP)
b.attach_xdp(device, fn, 0)
b.attach_xdp(dev2, fn, 0)

f_egress = b.load_func("handle_egress", BPF.SCHED_CLS)
ipr.tc("add-filter", "bpf", eth, ':1', fd=f_egress.fd, name=f_egress.name,
        parent='ffff:fff3', classid=1, direct_action=True)
ipr.tc("add-filter", "bpf", eth2, ':1', fd=f_egress.fd, name=f_egress.name,
        parent='ffff:fff3', classid=1, direct_action=True)

out_file = f"{log_dir}/{sw}B_{tw}ms.txt"
f = open(f"{out_file}", 'a')

def unsignedToSigned(n, byte_count): 
  return int.from_bytes(n.to_bytes(byte_count, 'little', signed=False), 'little', signed=True)

def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(4, byteorder="big")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    ip_xor = data.init_addr.to_bytes(4, 'little')
    eno1 = socket.inet_aton("10.50.1.2")
    res_ip = socket.inet_ntoa(bitwise_xor_bytes(ip_xor, eno1))
    if(re.match("10.50.1.*", res_ip)):
        print(f"INIT FID -> SADDR:{res_ip}, PORT:{data.init_port}, PROTO:{data.init_proto}, SZ:{data.init_sz}, T:{unsignedToSigned(data.init_tm, 8)}", end=" ", file=f)
    else:
        print(f"INIT FID -> SADDR:{ip_xor}, PORT:{data.init_port}, PROTO:{data.init_proto}, SZ:{data.init_sz}, T:{unsignedToSigned(data.init_tm, 8)}", end=" ", file=f)

    print(f"RESULT -> DADDR:{socket.inet_ntoa(data.res_addr.to_bytes(4, 'little'))}, DPORT:{data.res_port}, PROTO:{data.res_proto}, SZ:{data.res_sz}, T:{unsignedToSigned(data.res_tm, 8)}", file=f)

b["output"].open_ring_buffer(print_event)
print("Setup complete. Listening for events...")
while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        break

b.remove_xdp(device, 0)
ipr.tc("del-filter", "bpf", eth, ':1', protocol=0, prio=0xc000, parent='ffff:fff3')
b.remove_xdp(dev2, 0)
ipr.tc("del-filter", "bpf", eth2, ':1', protocol=0, prio=0xc000, parent='ffff:fff3')
f.close()
exit()
