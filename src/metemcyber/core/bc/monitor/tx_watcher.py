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
import shelve
import sys
from pprint import pprint
from time import sleep
from typing import List, Tuple


def main(args):
    with shelve.open(args.db, 'r') as ddb:
        earliest = ddb.get('earliest', 1)
        latest = ddb.get('latest', 1)
        start = args.start if args.start > 0 else latest + args.start
        start = min(max(start, earliest), latest)

        # quick print already dumped transactions.
        keys = [key for key in ddb.keys() if key.isdecimal() and int(key) >= start]
        for key in sorted(keys, key=int):
            for tx0 in ddb.get(key):
                pprint(tx0)

    # poll new transactions and print them.
    block = latest
    while True:
        try:
            sleep(1)
            with shelve.open(args.db, 'r') as ddb:
                if block >= ddb.get('latest', 0):
                    continue
                txs = ddb.get(str(block))
                if txs:
                    for tx0 in txs:
                        pprint(tx0)
                else:
                    print(f'\r{block}', end='', file=sys.stderr)
                block += 1
        except KeyboardInterrupt:
            break


OPTIONS: List[Tuple[str, str, dict]] = [
    ('-d', '--db', dict(action='store', required=True)),
    ('-s', '--start', dict(action='store', type=int, default=0)),
]
ARGUMENTS: List[Tuple[str, dict]] = [
]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, opts in OPTIONS:
        PARSER.add_argument(sname, lname, **opts)
    for name, opts in ARGUMENTS:
        PARSER.add_argument(name, **opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
