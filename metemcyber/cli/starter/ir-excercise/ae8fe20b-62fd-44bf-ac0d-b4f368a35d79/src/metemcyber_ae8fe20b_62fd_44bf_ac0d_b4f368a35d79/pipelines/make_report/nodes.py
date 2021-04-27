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
from typing import List, Optional
import webbrowser

import pandas as pd
from bs4 import BeautifulSoup
from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.shortcuts import yes_no_dialog, message_dialog

log = logging.getLogger(__name__)


def make_report_template(
        discovered_network_ioc: pd.DataFrame,
        discovered_endpoint_ioc: pd.DataFrame,
        source_of_truth_with_family: pd.DataFrame) -> str:
    return "sample"
