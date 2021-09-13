"""
Merge all day binned pcaps in folder into single file.
"""
import sys
from pcap import get_pcaps_fnames

from pypacker import ppcap
from pypacker.layer12 import ethernet


if len(sys.argv) != 2:
    print('Usage: python3 merge_folder_to_single_pcap.py PCAP_FOLDER')
    exit(1)

pcap_dir = sys.argv[1]

pwriter = ppcap.Writer(filename=f'{pcap_dir}.pcap', linktype=ppcap.DLT_EN10MB)

for fname in get_pcaps_fnames(pcap_dir):
    preader = ppcap.Reader(filename=fname)
    for ts, buf in preader:
        eth = ethernet.Ethernet(buf)
        if eth[ethernet.Ethernet] is not None:
            pwriter.write(eth.bin(), ts=ts)
    preader.close()

pwriter.close()