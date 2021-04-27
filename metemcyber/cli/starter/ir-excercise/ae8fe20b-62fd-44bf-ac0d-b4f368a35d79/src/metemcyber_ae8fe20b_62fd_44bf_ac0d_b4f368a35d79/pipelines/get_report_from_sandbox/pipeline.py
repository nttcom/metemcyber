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

from kedro.pipeline import Pipeline, node
from .nodes import search_report_from_anyrun, get_report_from_anyrun, extract_data_from_anyrun_html


def create_pipeline(**kwargs):
    return Pipeline(
        [
            node(
                func=search_report_from_anyrun,
                inputs="source_of_truth",
                outputs="anyrun_url",
                name="search_report_from_anyrun",
            ),
            node(
                func=get_report_from_anyrun,
                inputs="anyrun_url",
                outputs=None,   # Save html file by yoursself
                name="get_report_html"
            ),
            node(
                func=extract_data_from_anyrun_html,
                inputs=["anyrun_url", "anyrun_html", "source_of_truth"],
                outputs="source_of_truth_from_anyrun",
                name="extract_data_from_anyrun_html",
            ),
        ]
    )
