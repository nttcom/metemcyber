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

import argparse
import os
from argparse import Namespace
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException

from metemcyber.core.bc.monitor.tx_counter import ARGUMENTS, OPTIONS, str2counter


def _setup_counter_args() -> Namespace:
    config_path = os.environ.get('TX_MONITOR_CONFIG_PATH')
    if not config_path:
        raise Exception('Missing environment variable: TX_MONITOR_CONFIG_PATH')
    parser = argparse.ArgumentParser()
    for sname, lname, opts in OPTIONS:
        parser.add_argument(sname, lname, **opts)
    for name, opts in ARGUMENTS:
        parser.add_argument(name, **opts)
    args_array = ['-c', config_path]
    return parser.parse_args(args=args_array)


os.environ['TZ'] = 'UTC'
COUNTER_ARGS = _setup_counter_args()
app = FastAPI()


@app.post('/tx_counter')
async def post_receiver(queries: List[dict]) -> List[dict]:
    result = []
    for query in queries:
        try:
            if not query.get('class'):
                raise Exception('Missing parameter: class')
            counter_class = str2counter(query['class'])
            options = query.get('options', {})
            counter = counter_class(COUNTER_ARGS, options)
            result.append(counter.summarize(COUNTER_ARGS, options))
        except Exception as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
    return result


if __name__ == '__main__':
    uvicorn.run(app, port=38000, host='0.0.0.0')
