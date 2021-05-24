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

import logging
import sys
import urllib
from typing import Any, Dict, Optional

from bs4 import BeautifulSoup, element
from prompt_toolkit.shortcuts import yes_no_dialog


def search_report_from_anyrun(source_of_truth: Dict[str, Any]) -> Optional[str]:
    """Node for searching report from anyrun
    """
    log = logging.getLogger(__name__)
    sha256_hash = source_of_truth['sha256'].lower()
    anyrun_url = f"https://any.run/report/{sha256_hash}"

    req = urllib.request.Request(anyrun_url)
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36")
    with urllib.request.urlopen(req) as response:
        status = response.getcode()
        if status == 200:
            log.info("This file exists: %s", anyrun_url)
            return anyrun_url
        else:
            log.warning("File not found: %s", sha256_hash)

    return None


def get_report_from_anyrun(anyrun_url: str):
    """Node for getting text report from anyrun
    """
    log = logging.getLogger(__name__)
    log.info("This file exists: {anyrun_url}")
    # ここで手作業を実施する
    result = yes_no_dialog(
        title='Manual action required',
        text=f'{anyrun_url} にアクセスして\ntextレポートのhtmlファイルを 02_intermediate/input.html に保存してください\n'
        'ダウンロードしたらYesを、中断する場合はNoを選択してください。').run()
    if not result:
        log.warning('Abort workflow because aborting save html file')
        sys.exit()
    return result


def extract_data_from_anyrun_html(
    exist_htmlfile: bool,
    anyrun_url: str,
    html: str,
    source_of_truth: Dict[str, Any]
) -> Dict[str, Any]:
    """Node for parasing anyrun text report html and extract IOC.
    """
    if not exist_htmlfile:
        sys.exit()
    soup = BeautifulSoup(html, "html.parser")

    # Create data to insert source_of_truth
    report = {}
    report['name'] = 'any.run'
    report['result'] = anyrun_url

    # extract threats
    threats = []
    for badge_tag in soup.find_all('h2', class_="badge badge-secondary"):
        threats.append(badge_tag.text)
    report['threats'] = threats

    # extract dns
    report['network_activities'] = {}
    dns = soup.find(class_='dnsReqs')
    dns_list = []
    for row in dns.find_all("tr")[1:]:
        domain, ip, reputation = [div.text.strip() for div in row.find_all("td")]
        ip = ip.split()
        dns_list.append(
            {
                'domain': domain,
                'ip': ip,
                'reputation': reputation,
            }
        )
    report['network_activities']['dns'] = dns_list

    # extract http
    http = soup.find(class_='httpReqs')
    http_list = []
    for row in http.find_all("tr")[1:]:
        pid, process, method, ip, url, cn, type, size, reputation = [
            div.text.strip() for div in row.find_all("td")]
        http_list.append(
            {
                'pid': pid,
                'process': process,
                'method': method,
                'ip': ip,
                'url': url,
                'cn': cn,
                'size': size,
                'reputation': reputation,
            }
        )
    report['network_activities']['http'] = http_list

    # file
    droppedfiles = []
    for h4 in soup.find_all('h4'):
        if h4.text == 'Dropped files':
            dropped_files_ele = list(h4.next_siblings)
            for ele in dropped_files_ele:
                if isinstance(ele, element.Tag):
                    row_list = ele.find_all(class_="table-row")
                    for row in row_list[1:]:
                        pid = row.find(class_="table-item pid").text
                        filename = row.find(class_="table-item filename").text
                        path = row.find(class_="table-item path").text
                        extension = row.find(class_="table-item extension").text
                        hash_value = row.find_all(class_="hash")
                        md5 = hash_value[0].text.split()[-1]
                        sha256 = hash_value[1].text.split()[-1]
                        droppedfiles.append(
                            {
                                'pid': pid,
                                'filename': filename,
                                'path': path,
                                'extension': extension,
                                'md5': md5,
                                'sha256': sha256
                            }
                        )
    report['file_activities'] = droppedfiles

    # registry
    registry_list = []
    registry = soup.find(class_='process__registry')
    for row in registry.find_all(class_="table-row")[1:]:
        pid, process, operation, key, name, value = [
            div.text for div in row.find_all("div")]
        registry_list.append(
            {
                'pid': pid,
                'process': process,
                'operation': operation,
                'key': key,
                'name': name,
                'value': value,
            }
        )
    report['registry_activities'] = registry_list

    source_of_truth['reports'].append(report)

    return source_of_truth  # source_of_truthに追記した新規ファイルを作成する
