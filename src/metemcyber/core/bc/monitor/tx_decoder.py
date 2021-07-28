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
import glob
import json
import os
import pprint
import sys
from time import sleep
from typing import Any, Dict, List, Tuple

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.exceptions import BlockNotFound

from metemcyber.core.bc.monitor.tx_db import TransactionDB

ABIS_DIR = f'{os.path.dirname(os.path.abspath(__file__))}/../contracts_data'


def get_blocks_by_timestamp(
        tdb: TransactionDB, min_timestamp: int = 0, max_timestamp: int = 0) -> List[int]:
    if not tdb.get('timestamps'):
        raise Exception('Wrong type of database. (should be a decoded database)')
    return [block for block, timestamp in tdb.get('timestamps').items()
            if (min_timestamp <= 0 or timestamp >= min_timestamp) and
               (max_timestamp <= 0 or timestamp < max_timestamp)
            ]


class ABIManager:
    abis: Dict[str, dict]  # {contract_id}-{contract_version} : abi
    contracts: Dict[Any, str]  # contract : {contract_id}-{contract_version}
    cached_contracts: Dict[ChecksumAddress, Any]  # to address: contract

    def __init__(self):
        self.abis = {}
        self.contracts = {}
        self.cached_contracts = {}
        for comb_fname in glob.iglob(f'{ABIS_DIR}/*.combined.json-*'):
            bname = os.path.basename(comb_fname)
            contract_name = bname.split('.')[0]
            contract_ver = bname.split('-')[-1]
            contract_id = f'{contract_name}.sol:{contract_name}'
            key = f'{contract_id}-{contract_ver}'
            with open(comb_fname, 'r') as fin:
                comb_json = json.load(fin)['contracts'][contract_id]
            abi = json.loads(comb_json['metadata'])['output']['abi']
            self.abis[key] = abi
            contract = Web3().eth.contract(abi=abi)
            self.contracts[contract] = key

    @staticmethod
    def fix_funcname(contract_key, func) -> str:
        contract_name = contract_key.split(':')[-1]  # contains '-{version}'
        contract_name = contract_name.split('-')[0]  # remove version
        return f'{contract_name}.{func.fn_name}'

    def decode(self, tx0: dict) -> dict:
        to_addr = tx0.get('to')
        input_data = tx0.get('input')

        if not input_data:  # nothing to fix
            return tx0

        if not to_addr:  # maybe deploy
            contract_address = tx0['x_tx_receipt'].contractAddress
            if contract_address:
                tx0['deployed_address'] = contract_address
                tx0['function'] = '(deploy)'
                tx0['input'] = f'(bytecode length = {len(input_data)})'
            else:
                tx0['input'] = f'(data length = {len(input_data)})'
            return tx0

        if to_addr in self.cached_contracts.keys():  # use try cache
            cache = self.cached_contracts[to_addr]
            contract_key = self.contracts[cache]
            try:
                func, dec_data = cache.decode_function_input(input_data)
                tx0['function'] = self.fix_funcname(contract_key, func)
                tx0['input'] = dec_data
                return tx0
            except Exception:
                pass

        for contract, contract_key in self.contracts.items():  # try with any
            try:
                func, dec_data = contract.decode_function_input(input_data)
                tx0['function'] = self.fix_funcname(contract_key, func)
                tx0['input'] = dec_data
                return tx0
            except Exception:
                pass

        # give up decoding
        tx0['input'] = f'(data length = {len(input_data)})'
        return tx0


class TransactionDecoder:
    tdb_raw: TransactionDB
    tdb_dec: TransactionDB
    abi_mgr: ABIManager
    conf: dict

    def __init__(self, config_filepath):
        with open(config_filepath, 'r') as fin:
            self.conf = json.load(fin).get('decoder', {})
        self.tdb_raw = TransactionDB(None, self.conf['db_filepath_raw'])
        endpoint = self.tdb_raw.get('endpoint') or ''
        assert len(endpoint) > 0
        self.tdb_dec = TransactionDB(endpoint, self.conf['db_filepath_decoded'])
        self.abi_mgr = ABIManager()
        self.tdb_dec.update('codesize', self.tdb_raw.get('codesize'))
        self.timestamps = self.tdb_dec.get('timestamps') or {}

    def fix_startblock(self) -> int:
        assert self.tdb_dec
        tmp = int(self.conf.get('start_block', 1))
        if tmp > 0:
            return tmp
        tmp += self.tdb_dec.latest
        return tmp if tmp > 0 else 1

    def simplify_tx(self, tx0: dict) -> dict:
        skip_keys = {'blockHash', 'hash', 'nonce', 'r', 's', 'v', 'x_tx_receipt', 'x_block'}
        skip_keys_on_zero = {'to', 'input', 'value'}
        tx0['x_receipt_status'] = tx0['x_tx_receipt'].status
        if tx0.get('input'):
            tx0 = self.abi_mgr.decode(tx0)
        for key in skip_keys:
            tx0.pop(key, None)
        for key in skip_keys_on_zero:
            if tx0.get(key):
                continue
            del tx0[key]
        return tx0

    def _sync_db(self, latest: int):
        self.tdb_dec.update_latest(latest)
        self.tdb_dec.update('timestamps', self.timestamps)

    def run(self):
        assert self.tdb_raw
        assert self.tdb_dec
        print_blocknum = bool(self.conf.get('print_blocknum', True))
        print_decoded = bool(self.conf.get('print_decoded', False))
        exit_on_head = bool(self.conf.get('exit_on_head', False))
        ext_lf = '\n' if print_blocknum else ''
        block = self.fix_startblock()

        self.tdb_raw.open(readonly=True)  # start with keep-alive mode
        self.tdb_dec.open(readonly=False)

        try:
            for block in self.tdb_raw.stored_blocks(minimum=block):
                print(f'\r{block}' if print_blocknum else '', end='', file=sys.stderr)
                for idx, tx0 in enumerate(self.tdb_raw.load(block, None)):
                    self.timestamps[block] = tx0['x_timestamp']
                    tx0 = self.simplify_tx(dict(tx0))
                    self.tdb_dec.store(block, idx, tx0)
                    if print_decoded:
                        pprint.pprint(tx0)
        except KeyboardInterrupt:
            self._sync_db(block - 1)  # block may be incomplete
            print(f'{ext_lf}decoder interrupted at block: {block}')
            return

        self.tdb_raw.close()  # switch out from keep-alive mode
        self.tdb_dec.close()

        block += 1
        while True:
            try:
                print(f'\r{block}' if print_blocknum else '', end='', file=sys.stderr)
                for idx, tx0 in enumerate(self.tdb_raw.load(block, None)):
                    self.timestamps[block] = tx0['x_timestamp']
                    tx0 = self.simplify_tx(dict(tx0))
                    self.tdb_dec.store(block, idx, tx0)
                    if print_decoded:
                        pprint.pprint(tx0)
                # Note: skip updating latest if block has no txs, for performance.
                block += 1
                continue
            except KeyboardInterrupt:
                self._sync_db(block - 1)  # block may be incomplete
                print(f'{ext_lf}decoder interrupted at block: {block}')
                return
            except BlockNotFound:
                if exit_on_head:
                    self._sync_db(block - 1)
                    print(f'{ext_lf}decoder stopped at the head: {block}')
                    return
            try:
                self._sync_db(block - 1)  # lazy update
                sleep(1)
            except KeyboardInterrupt:
                print(f'{ext_lf}decoder interrupted at block: {block}')
                return
        self._sync_db(block - 1)
        print(f'{ext_lf}decoder stopped by error at block: {block}')


def main(args):
    decoder = TransactionDecoder(args.config)
    decoder.run()


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
