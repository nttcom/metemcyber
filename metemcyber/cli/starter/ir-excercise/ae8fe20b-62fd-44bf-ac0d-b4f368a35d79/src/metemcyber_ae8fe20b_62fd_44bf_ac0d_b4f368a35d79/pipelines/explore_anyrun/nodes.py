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

import urllib
import logging
from typing import List
import webbrowser

import pandas as pd
from bs4 import BeautifulSoup
from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.shortcuts import yes_no_dialog, message_dialog

log = logging.getLogger(__name__)


def check_anyrun(sha256_hash: str) -> str:
    anyrun_url = f"https://any.run/report/{sha256_hash}"

    req = urllib.request.Request(anyrun_url)
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36")
    with urllib.request.urlopen(req) as response:
        status = response.getcode()
        if status == 200:
            return anyrun_url

    return None


# def import_data_from_anyrun(model: pd.DataFrame) -> pd.DataFrame:
def import_data_from_anyrun(source_of_truth: pd.DataFrame):

    sha256_hash = source_of_truth['sha256']
    anyrun_url = check_anyrun(sha256_hash)
    if anyrun_url:
        log.info(f"This file exists: {anyrun_url}")
        # ここで手作業を実施する
        message_dialog(
            title='Manual action required',
            text=f'{anyrun_url} にアクセスして\nhtmlファイルを 02_intermediate/input.html に保存してください'
        ).run()
    else:
        log.warning(f"File not found: {sha256_hash}")


def extract_data_from_anyrun_html(html: str,
                                  source_of_truth: pd.DataFrame) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    tags = []
    for info_tag in soup.find('div', class_="info__tags").find_all('a'):
        tags.append(info_tag.text)
    print(tags)

    source_of_truth['reports'][0]['threats'].extend(tags)
    log.info(f"source of truthの情報を更新しました。")
    log.warning(f"マルウェアのIOCを 03_primary/ioc.csv に格納してください")
    message_dialog(
        title='Manual action required',
        text=f'03_primary/ioc.csv に使用するマルウェアのIOCを格納してください'
    ).run()
    return source_of_truth
