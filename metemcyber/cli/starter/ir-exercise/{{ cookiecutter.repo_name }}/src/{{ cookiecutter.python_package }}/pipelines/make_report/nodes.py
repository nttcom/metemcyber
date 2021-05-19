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

import json
import logging
import re
from typing import Any, Dict

import pandas as pd
from jinja2 import Template
from pymisp import MISPEvent

log = logging.getLogger(__name__)


def make_misp_json(
    discovered_network_ioc: pd.DataFrame,
    discovered_endpoint_ioc: pd.DataFrame,
    source_of_truth_with_family: pd.DataFrame,
) -> Dict[str, Any]:
    """Node for creating MISP report json
    """
    # create MISP event
    event_obj = MISPEvent()

    event_obj.add_tag(name="tlp:green")

    date = source_of_truth_with_family['reports'][0]['timestamp']
    event_obj.info = f'{date} AV Alert'

    # Add malware inforamtion
    sha256 = source_of_truth_with_family['sha256']
    event_obj.add_attribute('sha256', value=sha256)

    # Add network information
    for hostname in discovered_network_ioc['value'].unique():
        is_ipadd = re.match(
            "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
            hostname)
        if is_ipadd:
            event_obj.add_attribute('ip-dst', value=hostname)
        else:
            event_obj.add_attribute('domain', value=hostname)

    # Add endpoint IOC
    for registry in discovered_endpoint_ioc['Path'].unique():
        event_obj.add_attribute('regkey', value=registry)

    misp_dict = dict()
    misp_dict['Event'] = json.loads(event_obj.to_json())
    return misp_dict


def make_report(
    discovered_network_ioc: pd.DataFrame,
    discovered_endpoint_ioc: pd.DataFrame,
    source_of_truth_with_family: pd.DataFrame,
    report_template: str,
) -> str:
    """Node for creating Markdown report
    """
    # 共通するパラメータの取得
    parameters = {
        'date': source_of_truth_with_family['reports'][0]['timestamp'],
        'malware_family': source_of_truth_with_family['malware_family'],
        'misp_event_name': 'sample_event',
    }
    # テンプレートの取得
    template = Template(report_template)
    if len(discovered_network_ioc) > 0 or len(discovered_endpoint_ioc) > 0:
        # IOCが存在した場合の処理
        parameters['infection'] = True

        # IOCをテーブルに変換
        parameters['network_iocs'] = discovered_network_ioc.to_markdown()
        parameters['endpoint_iocs'] = discovered_endpoint_ioc.to_markdown()

        return template.render(**parameters)
    else:
        # IOCが存在しなかった場合の処理
        parameters['infection'] = False

        # 感染確認用のテンプレートの取得
        return template.render(**parameters)
