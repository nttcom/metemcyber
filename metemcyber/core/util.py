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

from configparser import ConfigParser
from random import randint
from typing import Any, Dict, Optional

LOCAL_PORT_RANGE_FILE = '/proc/sys/net/ipv4/ip_local_port_range'
LOCAL_PORT_MIN = 0
LOCAL_PORT_MAX = 0


def get_random_local_port() -> int:
    # pylint: disable=global-statement
    global LOCAL_PORT_MIN, LOCAL_PORT_MAX
    if LOCAL_PORT_MAX == 0:
        try:
            with open(LOCAL_PORT_RANGE_FILE, 'r') as fin:
                p_min, p_max = fin.readline().strip().split('\t', 1)
                LOCAL_PORT_MIN = int(p_min)
                LOCAL_PORT_MAX = int(p_max)
        except Exception:
            LOCAL_PORT_MIN = 50000
            LOCAL_PORT_MAX = 59999
    return randint(LOCAL_PORT_MIN, LOCAL_PORT_MAX)


def merge_config(file_path: Optional[str], defaults: Dict[str, Dict[str, Any]],
                 base_config: Optional[ConfigParser] = None) -> ConfigParser:
    config = base_config if base_config else ConfigParser()
    if file_path:
        if file_path not in config.read(file_path):
            raise Exception(f'Load config failed: {file_path}')
    for sect, sect_item in defaults.items():
        if not config.has_section(sect):
            config.add_section(sect)
        for key, val in sect_item.items():
            if not config[sect].get(key):
                config.set(sect, key, val)
    return config
