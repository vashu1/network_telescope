import os
import pathlib
from pypacker.structcbs import pack_IIII
from typing import List, Tuple


def get_pcaps_fnames(pcap_dir: str) -> List[str]:
    pcap_names = [str(pathlib.Path(root) / file) for root, subdirs, files in os.walk(pcap_dir) for file in files if
                   file.endswith('.pcap')]
    pcap_names.sort()
    return pcap_names


def fname_to_day_and_honeypot_ip(pcap_path: str) -> Tuple[str, str]:
    # 'icmp/ICMP_2019-09-05_to_172.31.21.94.pcap' -> ['2019-09-05', '172.31.21.94']
    pcap_name = pathlib.Path(pcap_path).stem
    date, ip = pcap_name.split('_to_')
    if '_' in date:
        date = date.split('_')[-1]
    return date, ip