from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip

# due to massive SIP scan, one pcap is 174M, so we filter out single IP
fname = '2019-09-13_to_172.31.21.94.pcap'
IP = '81.228.38.134'

writer = ppcap.Writer(filename=f'{fname}', linktype=ppcap.DLT_EN10MB)
preader = ppcap.Reader(filename='pcaps/{fname}')
for ts, buf in preader:
    eth = ethernet.Ethernet(buf)
    if eth[ethernet.Ethernet, ip.IP] is not None:
        if eth[ip.IP].src_s == IP or eth[ip.IP].dst_s == IP:
            continue
        writer.write(eth.bin(), ts=ts)

writer.close()