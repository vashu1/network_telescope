"""
Dataset source - https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP

Import of module takes about half a minute because of data upload.
"""
import netaddr
import pandas as pd
import intervaltree
import pathlib
from typing import Optional

GEO_FEED_FNAME = 'IP2LOCATION-LITE-DB1.CSV'

country_code2name = {}
ip2country_tree = intervaltree.IntervalTree()

def _load_ip2location_dataset() -> None:
    dataset_path = pathlib.Path(__file__).parent.resolve() / GEO_FEED_FNAME
    df = pd.read_csv(dataset_path, names=['start', 'end', 'code', 'name'], header=None)
    for _, row in df.iterrows():
        start, end, country_code, country_name = row
        if country_code == '-':
            continue
        country_code2name[country_code] = country_name
        ip2country_tree[start:end] = country_code

def get_ip_country(ip_str: str) -> Optional[str]:
    ip = netaddr.IPAddress(ip_str)
    return get_ipint_country(int(ip))

def get_ipint_country(ip_int: int) -> Optional[str]:
    interval_set = ip2country_tree[ip_int]
    if not interval_set:
        return None
    interval, = interval_set
    return interval.data

def get_country_name(country_code: str) -> str:
    return country_code2name[country_code]

# load data once at import
if not country_code2name and not ip2country_tree:
    print(f'{GEO_FEED_FNAME} upload can take up to a minute!')
    _load_ip2location_dataset()