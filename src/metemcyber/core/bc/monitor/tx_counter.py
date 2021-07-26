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
from argparse import Namespace
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Type, Union

from eth_typing import ChecksumAddress

import metemcyber.core.bc.monitor.tx_util as util
from metemcyber.core.bc.monitor.tx_db import TransactionDB
from metemcyber.core.bc.monitor.tx_decoder import get_blocks_by_timestamp
from metemcyber.core.bc.monitor.tx_metadata_manager import MetadataManager

DEFAULT_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


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

    def __init__(self, args: Namespace, options: dict):
        with open(args.config, 'r') as fin:
            self.conf = json.load(fin).get('counter', {})
        self.dec_db = TransactionDB(None, self.conf['db_filepath_decoded'])
        self.meta = MetadataManager(args.config, readonly=True)
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
                assert btx.deployed
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

    @staticmethod
    def _get_timestamps(args: Namespace, opt: dict) -> Tuple[int, int]:
        date_format = (args.date_format if args.date_format else
                       opt['date_format'] if opt.get('date_format') else
                       DEFAULT_DATETIME_FORMAT)
        ts_min = int(datetime.strptime((args.start if args.start else
                                        opt['start'] if opt.get('start') else
                                        datetime.fromtimestamp(0).strftime(date_format)
                                        ),
                                       date_format).timestamp())
        ts_max = int(datetime.strptime((args.end if args.end else
                                        opt['end'] if opt.get('end') else
                                        datetime.now().strftime(date_format)
                                        ),
                                       date_format).timestamp())
        return ts_min, ts_max

    def summarize(self, args: Namespace, opt: dict) -> dict:
        opt_rev = opt.get('reverted', 'no').lower()
        if opt_rev not in {'both', 'yes', 'no'}:
            raise Exception(f'Invalid option for reverted: {opt.get("reverted")}')
        reverted = (True if opt_rev == 'yes' else
                    False if opt_rev == 'no' else
                    None)
        ts_start, ts_end = self._get_timestamps(args, opt)
        summary: dict = {}
        for block in get_blocks_by_timestamp(
                self.dec_db, min_timestamp=ts_start, max_timestamp=ts_end):
            for tx0 in self.dec_db.load(block, None):
                if reverted not in {None, tx0.get('x_receipt_status') != 1}:
                    continue
                for entry in self.tx_to_entry(tx0):
                    summary = util.safe_inc(summary, entry)
        return summary


class Waixu(TransactionCounter):
    include_catalogs: List[ChecksumAddress] = []
    exclude_catalogs: List[ChecksumAddress] = []
    include_brokers: List[ChecksumAddress] = []
    exclude_brokers: List[ChecksumAddress] = []

    def __init__(self, args: Namespace, options: dict):
        super().__init__(args, options)
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


def str2counter(classname: str) -> Type[TransactionCounter]:
    counter_class = (Waixu if classname == 'Waixu' else
                     TransactionCounter if classname == 'Simple' else
                     None)
    if not counter_class:
        raise Exception(f'Invalid counter classname: {classname}')
    return counter_class


def main(args: Namespace):
    with open(args.config, 'r') as fin:
        queries = [q for q in json.load(fin).get('queries', []) if not q.get('disable')]
    result = []
    for query in queries:
        options = query.get('options', {})
        counter = str2counter(query['class'])(args, options)
        summary = counter.summarize(args, options)
        result.append(summary)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))


OPTIONS: List[Tuple[str, str, dict]] = [
    ('-c', '--config', dict(action='store', required=True)),
    ('-d', '--date_format', dict(action='store', required=False)),
    ('-s', '--start', dict(action='store', required=False)),
    ('-e', '--end', dict(action='store', required=False)),
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
