"""
Usage:
python3 top_ips_ports.py some.pcap

Output example:
167.99.227.94 total bytes: 97300 by port: [(5060, 43339), (5070, 6332), (27015, 5617)]
51.158.30.15 total bytes: 9025 by port: [(5060, 9025), (62567, 654), (58926, 652)]
134.122.85.244 total bytes: 6260 by port: [(5061, 4026), (5062, 3130), (5070, 896)]
...

(first ip would be the host)
"""
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from collections import Counter, defaultdict
import sys

def eth_ports(eth):
    if eth[tcp.TCP] is not None:
        return eth[tcp.TCP].sport, eth[tcp.TCP].dport
    elif eth[udp.UDP] is not None:
        return eth[udp.UDP].sport, eth[udp.UDP].dport
    else:
        return None, None

def scan(fname):
    top_count = Counter()
    top_ports = defaultdict(Counter)
    c = 0
    preader = ppcap.Reader(filename=fname)
    for ts, buf in preader:
        if not len(buf):
            continue
        eth = ethernet.Ethernet(buf)
        if eth[ethernet.Ethernet, ip.IP] is not None:
            stats = len(eth)  # use 1 to get packet count
            top_count[eth[ip.IP].src_s] += stats
            top_count[eth[ip.IP].dst_s] += stats
            sport, dport = eth_ports(eth)
            if sport and dport:
                for ip_val in [eth[ip.IP].src_s, eth[ip.IP].dst_s]:
                    for port in [sport, dport]:
                        top_ports[ip_val][port] += stats
        c +=1
        if c % 1000000 == 0:
            print(c/1000000, 'M')
        if len(top_count) > 1000000:
            for k in top_count:
                if top_count[k] < 10:
                    del top_count[k]
                    del top_ports[k]
    return top_count, top_ports

stats, ports = scan(sys.argv[1])

for cur_ip, _ in stats.most_common(30):
    print(cur_ip, 'total bytes:', stats[cur_ip], 'by port:', ports[cur_ip].most_common(3))