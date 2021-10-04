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
import json
import sys
from time import sleep
from typing import List, Tuple

from web3 import Web3
from web3.exceptions import BlockNotFound, ExtraDataLengthError
from web3.middleware import geth_poa_middleware
from web3.providers.rpc import HTTPProvider

from metemcyber.core.bc.monitor.tx_db import TransactionDB


class TransactionDumper:
    web3: Web3
    tdb: TransactionDB
    conf: dict
    codesize: dict

    def __init__(self, config_filepath):
        with open(config_filepath, 'r', encoding='utf-8') as fin:
            self.conf = json.load(fin).get('dumper', {})
        endpoint = self.conf['endpoint']
        db_filepath = self.conf['db_filepath_raw']

        self.web3 = Web3(HTTPProvider(endpoint))
        try:
            self.web3.eth.get_block('latest')
        except ExtraDataLengthError:
            self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.tdb = TransactionDB(endpoint, db_filepath)
        self.codesize = self.tdb.get('codesize') or {}

    def fix_startblock(self) -> int:
        assert self.tdb
        tmp = int(self.conf.get('start_block', 1))
        if tmp > 0:
            return tmp
        tmp += self.tdb.latest
        return tmp if tmp > 0 else 1

    def _sync_db(self, latest: int):
        self.tdb.update_latest(latest)
        self.tdb.update('codesize', self.codesize)

    def run(self):
        assert self.web3
        assert self.tdb
        retry = retry_max = int(self.conf.get('retry_max', 10))
        print_blocknum = bool(self.conf.get('print_blocknum', True))
        ext_lf = '\n' if print_blocknum else ''
        block = self.fix_startblock()

        self.tdb.open()  # start with keep-alive mode

        while retry >= 0:
            try:
                if print_blocknum:
                    print(f'\r{block}', end='', file=sys.stderr)
                num_tx = self.web3.eth.get_block_transaction_count(block)
                if num_tx > 0:
                    block_info = self.web3.eth.get_block(block)
                    for i in range(num_tx):
                        tx0 = dict(self.web3.eth.get_transaction_by_block(block, i))
                        if tx0.get('hash'):
                            # append tx_receipt as an extra data
                            tx0['x_tx_receipt'] = self.web3.eth.get_transaction_receipt(tx0['hash'])
                        if self.codesize.get(tx0['from']) is None:
                            self.codesize[tx0['from']] = len(self.web3.eth.get_code(tx0['from']))
                        if tx0.get('to') and self.codesize.get(tx0['to']) is None:
                            self.codesize[tx0['to']] = len(self.web3.eth.get_code(tx0['to']))
                        tx0['x_timestamp'] = block_info.timestamp
                        tx0['x_block'] = block_info  # allow redundant when num_tx > 1
                        self.tdb.store(block, i, tx0)  # latest is also updated
                block += 1
                retry = retry_max  # reset on succeeded
                continue
            except KeyboardInterrupt:
                self._sync_db(block - 1)  # update before quit
                print(f'{ext_lf}dumper interrupted at block: {block}')
                return
            except BlockNotFound:
                if self.conf.get('exit_on_head', False):
                    self._sync_db(block - 1)
                    print(f'{ext_lf}dumper stopped at the head: {block}')
                    return
                self.tdb.close(allow_redundant=True)  # switch out from keep-alive mode
                sleep_sec = 1
                retry = retry_max  # reset on polling
            except Exception as err:
                print(f'[ERROR] {err}')
                sleep_sec = int(self.conf.get('retry_interval_sec', 1))
                retry -= 1

            try:
                self._sync_db(block - 1)  # lazy update
                sleep(sleep_sec)
            except KeyboardInterrupt:
                print(f'{ext_lf}dumper interrupted at block: {block}')
                return

        self._sync_db(block - 1)
        print(f'{ext_lf}dumper stopped by error at block: {block}')


def main(args):
    dumper = TransactionDumper(args.config)
    dumper.run()


OPTIONS: List[Tuple[str, str, dict]] = [
    ('-c', '--config', dict(action='store', required=True)),
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
