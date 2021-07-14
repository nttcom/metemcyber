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
import re
from typing import Dict, List, Optional, Tuple, Type, Union

from eth_typing import ChecksumAddress

import metemcyber.core.bc.monitor.tx_util as util
from metemcyber.core.bc.monitor.tx_db import TransactionDB
from metemcyber.core.bc.monitor.tx_metadata_manager import MetadataManager


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
    include_to: List[ChecksumAddress] = []
    exclude_to: List[ChecksumAddress] = []
    include_from: List[ChecksumAddress] = []
    exclude_from: List[ChecksumAddress] = []

    def __init__(self, config_filepath: str, options: dict):
        with open(config_filepath, 'r') as fin:
            self.conf = json.load(fin).get('counter', {})
        self.dec_db = TransactionDB(None, self.conf['db_filepath_decoded'])
        self.meta = MetadataManager(config_filepath, readonly=True)
        self.dec_db.open(readonly=True)
        self.codesize = self.dec_db.get('codesize') or {}
        self.options = options
        if options.get('generic_filter'):
            rules = options['generic_filter']
            for key in ['include_to', 'exclude_to',
                        'include_from', 'exclude_from']:
                if rules.get(key):
                    if isinstance(rules[key], list):
                        setattr(self, key, rules[key])
                    elif isinstance(rules[key], str):
                        setattr(self, key, re.split('[,\\s]+', rules[key]))
                    else:
                        raise Exception(f'Invalid filter: {key}')

    def get_blocks(self, days: int = 0, hours: int = 0) -> List[int]:
        assert days >= 0 and hours >= 0
        border = -1
        hours += days * 24
        if hours > 0:
            latest = self.dec_db.latest
            border = latest - (hours * 3600 / 2)  # mine a block every 2 seconds.
        return self.dec_db.stored_blocks(minimum=border if border > 0 else None)

    def generic_filter(self, btx: BasicTx) -> bool:
        if ((self.include_to and btx.addr_to not in self.include_to) or
                (self.exclude_to and btx.addr_to in self.exclude_to)):
            return False
        if ((self.include_from and btx.addr_from not in self.include_from) or
                (self.exclude_from and btx.addr_from in self.exclude_from)):
            return False
        return True

    def tx_to_entry(self, tx0: dict) -> List[List[str]]:
        if not tx0:
            return []
        btx = BasicTx(tx0)
        if not self.generic_filter(btx):
            return []
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

    def summarize(self, opt: dict) -> dict:
        days = int(opt.get('days', 0))
        hours = int(opt.get('hours', 0))
        opt_rev = opt.get('reverted', 'no').lower()
        if opt_rev not in {'both', 'yes', 'no'}:
            raise Exception(f'Invalid option for reverted: {opt.get("reverted")}')
        reverted = (True if opt_rev == 'yes' else
                    False if opt_rev == 'no' else
                    None)
        summary: dict = {}
        for block in self.get_blocks(days=days, hours=hours):
            for tx0 in self.dec_db.load(block, None):
                if reverted not in {None, tx0.get('x_receipt_status') != 1}:
                    continue
                for entry in self.tx_to_entry(tx0):
                    summary = util.safe_inc(summary, entry)
        return summary

    def run(self, options: dict):
        summary = self.summarize(options)
        print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))


class Waixu(TransactionCounter):
    include_catalogs: List[ChecksumAddress] = []
    exclude_catalogs: List[ChecksumAddress] = []
    include_brokers: List[ChecksumAddress] = []
    exclude_brokers: List[ChecksumAddress] = []

    def __init__(self, config_filepath: str, options: dict):
        super().__init__(config_filepath, options)
        if options.get('waixu_filter'):
            rules = options['waixu_filter']
            for key in ['include_catalogs', 'exclude_catalogs',
                        'include_brokers', 'exclude_brokers']:
                if rules.get(key):
                    if isinstance(rules[key], list):
                        setattr(self, key, rules[key])
                    elif isinstance(rules[key], str):
                        setattr(self, key, re.split('[,\\s]+', rules[key]))
                    else:
                        raise Exception(f'Invalid filter: {key}')

    def tx_to_entry(self, tx0: dict) -> List[List[str]]:
        if not tx0:
            return []
        btx = BasicTx(tx0)
        if not self.generic_filter(btx):
            return []
        ret = []
        if btx.function == 'CTIBroker.buyToken':
            assert isinstance(btx.input_data, dict)
            catalog = btx.input_data['catalogAddress']
            if ((self.include_catalogs and catalog not in self.include_catalogs) or
                    (self.exclude_catalogs and catalog in self.exclude_catalogs)):
                return []
            if ((self.include_brokers and btx.addr_to not in self.include_brokers) or
                    (self.exclude_brokers and btx.addr_to in self.exclude_brokers)):
                return []
            token = btx.input_data['tokenAddress']
            ret.append(['waicu', catalog, 'tokens', token])
            ret.append(['waicu', 'total', 'tokens', token])
            ret.append(['waicu', catalog, 'buyers', btx.addr_from])
            ret.append(['waicu', 'total', 'buyers', btx.addr_from])
        else:
            if ((self.include_catalogs and btx.addr_to not in self.include_catalogs) or
                    (self.exclude_catalogs and btx.addr_to in self.exclude_catalogs)):
                return []
            if btx.function == 'CTICatalog.publishCti':
                ret.append(['waipu', btx.addr_to, 'publish', btx.addr_from])
                ret.append(['waipu', 'total', 'publish', btx.addr_from])
            elif btx.function == 'CTICatalog.unregisterCti':
                ret.append(['waipu', btx.addr_to, 'unregister', btx.addr_from])
                ret.append(['waipu', 'total', 'unregister', btx.addr_from])
        return ret


def parse_queries(queries: List[dict]) -> List[Tuple[Type[TransactionCounter], dict]]:
    ret = []
    for query in queries:
        counter_class = (Waixu if query['class'] == 'Waixu' else
                         TransactionCounter if query['class'] == 'Simple' else
                         None)
        if not counter_class:
            raise Exception(f'Invalid Counter classname: {query["class"]}')
        ret.append((counter_class, query.get('options', {})))
    return ret


def main(args):
    with open(args.config, 'r') as fin:
        queries = [q for q in json.load(fin).get('queries', []) if not q.get('disable')]
    for counter_class, options in parse_queries(queries):
        counter = counter_class(args.config, options)
        counter.run(options)


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
