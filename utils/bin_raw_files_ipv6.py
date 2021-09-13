"""
This utility splits several pcap files to day binned pcaps.

TCP is filtered out, ICMP is put to separate files.

Admin usage only.
"""
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip6
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from collections import OrderedDict
from datetime import datetime
import sys

MY_IP = '167.99.227.94'

MY_IP = '167.99.227.94'
FILES = [f'../../network_telescope_new/network_telescope_V6_{i}.pcap' for i in range(0, 8+1)] + ['network_telescope_9.pcap']

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
    print(f'{fname=}')
    c = 0
    dropped = 0
    preader = ppcap.Reader(filename=fname)
    for ts, buf in preader:
        eth = ethernet.Ethernet(buf)
        if eth[ethernet.Ethernet] is not None:
            if eth[tcp.TCP] is not None:  # drop all TCP
                #if eth[tcp.TCP].sport == 22 or eth[tcp.TCP].dport == 22:
                #    continue
                dropped += 1
                continue
            else:
                pass
            save_packet(ts, eth)
        c +=1
        if c % 100 == 0:
            print('saved', c, 'dropped', dropped)


print(f'{MY_IP=}')
pcap_files = FILES #sys.argv[1:]  # FILES
for fname in pcap_files:
    scan(fname)

close_writers()
