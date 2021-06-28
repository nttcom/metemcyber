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
from typing import Dict, List, Optional, Tuple, Union

from eth_typing import ChecksumAddress

import metemcyber.core.bc.monitor.tx_util as util
from metemcyber.core.bc.monitor.tx_db import TransactionDB
from metemcyber.core.bc.monitor.tx_metadata_manager import MetadataManager
from metemcyber.core.logger import get_logger

LOGGER = get_logger(name='counter', file_prefix='tx_monitor')


class BasicTx:
    blocknum: int
    index: int
    addr_from: ChecksumAddress
    addr_to: Optional[ChecksumAddress]
    deployed: Optional[ChecksumAddress]
    function: Optional[str]
    gas: int
    gas_price: int
    value: int
    input_data: Optional[Union[dict, str]]
    status: int
    contract: str
    method: str

    def __init__(self, tx0: dict):
        self.blocknum = tx0['blockNumber']
        self.index = tx0['transactionIndex']
        self.addr_from = tx0['from']
        self.addr_to = tx0.get('to')
        self.deployed = tx0.get('deployed_address')
        self.function = tx0.get('function')
        self.gas = tx0['gas']
        self.gas_price = tx0['gasPrice']
        self.value = tx0.get('value', 0)
        self.input_data = tx0.get('input')
        self.status = tx0['x_receipt_status']
        if self.function:
            try:
                self.contract, self.method = self.function.split('.', 1)
            except Exception:
                self.contract = '(Unknown)'
                self.method = self.function
        else:
            self.contract = '(Unknown)'
            self.method = '(Send ETHER)' if self.value > 0 else '(Unknown)'


class TransactionCounter:
    conf: dict
    dec_db: TransactionDB
    meta: MetadataManager
    codesize: Dict[ChecksumAddress, int]

    def __init__(self, config_filepath: str):
        with open(config_filepath, 'r') as fin:
            self.conf = json.load(fin).get('counter', {})
        self.dec_db = TransactionDB(None, self.conf['db_filepath_decoded'])
        self.meta = MetadataManager(config_filepath, readonly=True)
        self.dec_db.open(readonly=True)
        self.codesize = self.dec_db.get('codesize') or {}

    def fix_startblock(self) -> int:
        tmp = int(self.conf.get('start_block', 1))
        if tmp > 0:
            return tmp
        tmp += self.dec_db.latest
        return tmp if tmp > 0 else 1

    def get_blocks(self, days: int = 0, hours: int = 0) -> List[int]:
        assert days >= 0 and hours >= 0
        border = -1
        hours += days * 24
        if hours > 0:
            latest = self.dec_db.latest
            border = latest - (hours * 3600 / 2)  # mine a block every 2 seconds.
        return self.dec_db.stored_blocks(minimum=border if border > 0 else None)

    def tx_to_entry(self, tx0: dict) -> List[List[str]]:
        if not tx0:
            return []
        btx = BasicTx(tx0)
        ret = []
        if btx.contract == '(Unknown)':
            if btx.method == '(deploy)':
                btx.contract = self.meta.get(btx.deployed).get('name', '(Unknown)')
            elif btx.addr_to:
                btx.contract = self.meta.get(btx.addr_to).get('name') or (
                    'EOA' if self.codesize.get(btx.addr_to) == 0 else '(Unknown)')
        if btx.addr_to:
            ret.append(['receiver', btx.contract, btx.addr_to, btx.method, btx.addr_from])
            ret.append(['receiver', btx.contract, btx.addr_to, btx.method, 'total'])
        category = 'EOA' if self.codesize.get(btx.addr_from) == 0 else 'EOA?'
        ret.append(['sender', category, btx.addr_from, f'{btx.contract}.{btx.method}'])
        return ret

    def summarize(self, days: int = 0, hours: int = 0, reverted: Optional[bool] = False) -> dict:
        summary: dict = {}
        for block in self.get_blocks(days=days, hours=hours):
            for tx0 in self.dec_db.load(block, None):
                if reverted not in {None, tx0.get('x_receipt_status') != 1}:
                    continue
                for entry in self.tx_to_entry(tx0):
                    summary = util.safe_inc(summary, entry)
        return summary

    def run(self, *args, **kwargs):
        summary = self.summarize(*args, **kwargs)
        print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))


class Waixu(TransactionCounter):
    def tx_to_entry(self, tx0: dict) -> List[List[str]]:
        if not tx0:
            return []
        btx = BasicTx(tx0)
        ret = []
        if btx.function == 'CTIBroker.buyToken':
            assert isinstance(btx.input_data, dict)
            catalog = btx.input_data['catalogAddress']
            token = btx.input_data['tokenAddress']
            ret.append(['waicu', catalog, 'tokens', token])
            ret.append(['waicu', 'total', 'tokens', token])
            ret.append(['waicu', catalog, 'buyers', btx.addr_from])
            ret.append(['waicu', 'total', 'buyers', btx.addr_from])
        elif btx.function == 'CTICatalog.publishCti':
            ret.append(['waipu', btx.addr_to, 'publish', btx.addr_from])
            ret.append(['waipu', 'total', 'publish', btx.addr_from])
        elif btx.function == 'CTICatalog.unregisterCti':
            ret.append(['waipu', btx.addr_to, 'unregister', btx.addr_from])
            ret.append(['waipu', 'total', 'unregister', btx.addr_from])
        return ret


def main(args):
    for cname in args.classes:
        counter_class = (Waixu if cname == 'Waixu' else
                         TransactionCounter if cname == 'Simple' else
                         None)
        if not counter_class:
            raise Exception('Invalid ClassName: {cname}')
        counter = counter_class(args.config)
        counter.run(days=args.days, hours=args.hours,
                    reverted=(True if args.reverted == 'yes' else
                              False if args.reverted == 'no' else
                              None)
                    )


OPTIONS: List[Tuple[str, str, dict]] = [
    ('-d', '--days', dict(action='store', type=int, default=0, required=False)),
    ('-H', '--hours', dict(action='store', type=int, default=0, required=False)),
    ('-r', '--reverted', dict(choices=['yes', 'no', 'both'], default='no', required=False)),
    ('-c', '--config', dict(action='store', required=True)),
]

ARGUMENTS: List[Tuple[str, dict]] = [
    ('classes', dict(choices=['Waixu', 'Simple'], nargs='*')),
]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, opts in OPTIONS:
        PARSER.add_argument(sname, lname, **opts)
    for name, opts in ARGUMENTS:
        PARSER.add_argument(name, **opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
