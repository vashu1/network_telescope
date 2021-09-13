"""
This utility splits several pcap files to day binned pcaps.

TCP is filtered out, ICMP is put to separate files.

Admin usage only.
"""
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from pypacker.layer3.icmp import ICMP
from collections import OrderedDict
from datetime import datetime
import sys

MY_IP = '167.99.227.94'

#MY_IP = '172.31.21.94'
#FILES = ['../../network_telescope/network_telescope.pcap'] + [f'../../network_telescope/network_telescope{i}.pcap' for i in range(2, 15+1)]
#MY_IP = '167.99.227.94'
#FILES = [f'../../network_telescope_new/network_telescope_{i}.pcap' for i in range(0, 8+1)]

pcap_writers = OrderedDict()
prev_date = None


def save_packet(ts, eth):
    global prev_date
    if len(pcap_writers) > 64:
        _, file = pcap_writers.popitem(last=False)
        file.close()
    if ts/1e9 > 1:
        date = datetime.utcfromtimestamp(ts/1e9).strftime('%Y-%m-%d')
        prev_date = date
    else:
        date = prev_date
    if date not in pcap_writers:
        print(f'processing {date}')
        pcap_writers[date] = ppcap.Writer(filename=f'{date}_to_{MY_IP}.pcap', linktype=ppcap.DLT_EN10MB)
    pcap_writers[date].write(eth.bin(), ts=ts)


def close_writers():
    for k in pcap_writers:
        pcap_writers[k].close()


def scan(fname):
    c = 0
    preader = ppcap.Reader(filename=fname)
    for ts, buf in preader:
        eth = ethernet.Ethernet(buf)
        if eth[ethernet.Ethernet, ip.IP] is not None:
            cur_ip = eth[ip.IP].src_s if eth[ip.IP].dst_s in MY_IP else eth[ip.IP].dst_s
            if cur_ip.startswith('172.31'):  # AWS net
                continue
            if eth[tcp.TCP] is not None:  # drop all TCP
                #if eth[tcp.TCP].sport == 22 or eth[tcp.TCP].dport == 22:
                #    continue
                continue
            elif eth[ethernet.Ethernet, ip.IP, udp.UDP] is not None:
                # drop AWS dns
                if cur_ip == '169.254.169.123' and (eth[udp.UDP].sport == 123 or eth[udp.UDP].dport == 123):
                    continue
            else:
                pass
            save_packet(ts, eth)
        c +=1
        if c % 1000000 == 0:
            print(c/1000000, 'M')


print(f'{MY_IP=}')
pcap_files = sys.argv[1:]  # FILES
for fname in pcap_files:
    scan(fname)

close_writers()
