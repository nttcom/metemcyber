#
#    Copyright 2021, NTT Communications Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

import re
import logging
import datetime
from typing import Any, Dict, List, Tuple

import dpkt
import pandas as pd

log = logging.getLogger(__name__)


def search_from_pcap(
    packets_list: List[Tuple[float, bytes]],
    target_ioc: pd.DataFrame,
) -> pd.DataFrame:

    # Extract network ioc
    # print(target_ioc)
    network_ioc = target_ioc[target_ioc['category'].isin(['domain', 'ip'])]
    # print(network_ioc[['value']])
    matched_artifact: List[Tuple(float, str)] = []
    for ts, buf in packets_list:
        # try:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                ip_data = ip.data  # TCP or UDP
                if ip_data.dport == 53:
                    dns = dpkt.dns.DNS(ip_data.data)

                    for q in dns.qd:
                        if q.name in network_ioc['value'].values:
                            # calcurate timestamp
                            dt = datetime.datetime.fromtimestamp(ts)

                            matched_artifact.append(
                                (dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ'), q.name))

    # print(matched_artifact)
    df_matched = pd.DataFrame(matched_artifact, columns=['timestamp', 'value'])
    # print(df_matched)
    return df_matched


def convert_registry_path(win_path: str) -> str:
    win_path = re.sub(r"^HKEY_CURRENT_USER", r"HKCU", win_path)
    win_path = re.sub(r"^HKEY_USERS", r"HKU", win_path)
    win_path = re.sub(r"^HKEY_LOCAL_MACHINE", r"HKLM", win_path)
    win_path = re.sub(r"^HKEY_CLASSES_ROOT", r"HKCR", win_path)
    return win_path


def search_windows_log(
    df_windows: pd.DataFrame,
    target_ioc: pd.DataFrame,
) -> pd.DataFrame:
    windows_ioc = target_ioc[target_ioc['category'].isin(['registry'])]
    windows_ioc['value'] = windows_ioc['value'].apply(convert_registry_path)

    df_windows = df_windows.fillna({'Path': ''})
    df_windows['Path'] = df_windows['Path'].apply(convert_registry_path)
    matched_ioc = df_windows[df_windows['Path'].isin(windows_ioc['value'].values)]

    return matched_ioc


"""
def search_from_pcap(
        packets_list: List[Tuple[float, bytes]],
        search_domain_list: List[str]
    ) -> str:
    print(type(packets_list))
    print(packets_list)

    for ts, buf in packets_list:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            ip_data = ip.data #TCP or UDP
            if ip_data.sport == 53 or ip_data.dport == 53:
                dns = dpkt.dns.DNS(ip_data.data)
                print(dns.qd)
                if dns.qd in search_domain_list:
                    print(dns.qd)
        except:
            continue

    return None
"""
