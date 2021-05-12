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

from .nodes import make_misp_json, make_report


def create_pipeline(**kwargs):
    return Pipeline([
        node(
            func=make_report,
            inputs=["discovered_network_ioc",
                    "discovered_endpoint_ioc",
                    "source_of_truth_with_family",
                    "report_template"],
            outputs="generated_report",
            name="make_report",
        ),
        node(
            func=make_misp_json,
            inputs=["discovered_network_ioc",
                    "discovered_endpoint_ioc",
                    "source_of_truth_with_family"],
            outputs="misp_json",
            name="make_misp_json",
        ),
    ])
