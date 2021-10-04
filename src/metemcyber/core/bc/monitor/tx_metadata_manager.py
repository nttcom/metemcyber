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
from typing import Any, Dict, List, Optional, Tuple

from eth_typing import ChecksumAddress
from web3.exceptions import BlockNotFound

from metemcyber.core.bc.monitor.tx_db import TransactionDB

DEPLOYERS: Dict[ChecksumAddress, ChecksumAddress] = {}
CONTRACTS: Dict[ChecksumAddress, 'Contract'] = {}
CONTRACT_CLASSES: Dict[str, type] = {}


class Contract:
    address: ChecksumAddress
    version: int
    deployer: Optional[ChecksumAddress]
    meta: Dict[str, Any]

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def __init__(self, address: ChecksumAddress, version: int = 0,
                 deployer: Optional[ChecksumAddress] = None,
                 meta: Optional[dict] = None):
        self.address = address
        self.version = version
        self.deployer = deployer or DEPLOYERS.get(address)
        self.meta = meta or {}
        CONTRACTS[address] = self

    def to_dict(self) -> dict:
        return {
            'address': self.address,
            'name': self.name,
            'version': self.version,
            'deployer': self.deployer,
            'meta': self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Contract':
        contract_class = CONTRACT_CLASSES.get(data['name'])
        assert contract_class
        contract = contract_class(
            data['address'], data['version'], data.get('deployer'), data.get('meta', {}))
        return contract

    def update(self, tx0):
        pass


class CTIToken(Contract):
    def update(self, tx0):
        cname, func = tx0['function'].split('.', 1)
        assert self.name == cname
        if func in {'setEditable', 'addCandidates', 'removeCandidates', 'vote'}:
            self.version = max(self.version, 1)
            if func == 'setEditable':
                self.meta['editable'] = tx0['input']['anyoneEditable']
            elif func == 'addCandidates':
                self.meta['candidates'] = self.meta.get('candidates') or {}
                for desc in tx0['input']['new_candidates']:
                    index = len(self.meta['candidates'].keys())
                    self.meta['candidates'][index] = {
                        'index': index,
                        'score': 0,
                        'desc': desc,
                    }
            elif func == 'removeCandidates':
                self.meta['candidates'] = self.meta.get('candidates') or {}
                for index in tx0['input']['indexes']:
                    self.meta['candidates'][index].desc += ' (REMOVED)'  # fake remove
            elif func == 'vote':
                self.meta['candidates'] = self.meta.get('candidates') or {}
                self.meta['candidates'][tx0['input']['idx']]['score'] += tx0['input']['amount']


class CTICatalog(Contract):
    def update(self, tx0):
        cname, func = tx0['function'].split('.', 1)
        assert self.name == cname
        if func in {'setMembers'}:
            self.version = max(self.version, 1)
            if func == 'setMembers':
                self.meta['members'] = tx0['input']['members_']
        elif func in {'setPrivate', 'setPublic', 'authorizeUser', 'revokeUser'}:
            self.version = 0
        elif func in {'registerCti', 'modifyCti'}:
            token_address = tx0['input']['tokenURI']
            self.meta['tokens'] = self.meta.get('tokens') or {}
            self.meta['tokens'][token_address] = {
                'uuid': tx0['input']['uuid'],
                'title': tx0['input']['title'],
                'price': tx0['input']['price'],
                'operator': tx0['input']['operator'],
            }
            token = CONTRACTS.get(token_address) or CTIToken(token_address)
            token.meta['catalogs'] = token.meta.get('catalogs', [])
            if self.address not in token.meta['catalogs']:
                token.meta['catalogs'].append(self.address)
        elif func == 'unregisterCti':
            token_address = tx0['input']['tokenURI']
            self.meta['tokens'][token_address]['title'] += ' (REMOVED)'  # fake remove
            token = CONTRACTS.get(token_address) or CTIToken(token_address)
            if self.address in token.meta.get('catalogs', []):
                token.meta['catalogs'].remove(self.address)


class CTIBroker(Contract):
    pass


class CTIOperator(Contract):
    def update(self, tx0):
        cname, func = tx0['function'].split('.', 1)
        assert self.name == cname
        if func == 'history' and 'seeker' in tx0['input'].keys():
            self.version = max(self.version, 1)


class AddressGroup(Contract):
    pass


CONTRACT_CLASSES = {
    'CTIToken': CTIToken,
    'CTICatalog': CTICatalog,
    'CTIBroker': CTIBroker,
    'CTIOperator': CTIOperator,
    'AddressGroup': AddressGroup,
}


class MetadataManager:
    conf: dict
    tdb_dec: Optional[TransactionDB]
    tdb_meta: TransactionDB
    codesize: Dict[ChecksumAddress, int]

    def __new__(cls, *_args, **_kwargs):
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_filepath: str, readonly=False):
        if hasattr(self, 'conf') and self.conf:  # already initialized
            return
        with open(config_filepath, 'r', encoding='utf-8') as fin:
            self.conf = json.load(fin).get('metadata_manager', {})
        if readonly:
            self.tdb_dec = endpoint = None
        else:
            self.tdb_dec = TransactionDB(None, self.conf['db_filepath_decoded'])
            endpoint = self.tdb_dec.get('endpoint')
            assert endpoint and len(endpoint) > 0
            self.codesize = self.tdb_dec.get('codesize')
        self.tdb_meta = TransactionDB(endpoint, self.conf['db_filepath_meta'])
        self._load_meta()

    def _load_meta(self):
        assert not DEPLOYERS and not CONTRACTS
        DEPLOYERS.update(self.tdb_meta.get('deployers') or {})
        CONTRACTS.update({
            val['address']: Contract.from_dict(val)
            for val in (self.tdb_meta.get('contracts') or {}).values()
        })

    def _save_meta(self):
        self.tdb_meta.update('deployers', DEPLOYERS)
        self.tdb_meta.update('contracts', {addr: cnt.to_dict() for addr, cnt in CONTRACTS.items()})

    @staticmethod
    def get(address: ChecksumAddress) -> dict:
        if address not in CONTRACTS.keys():
            return {}
        return CONTRACTS[address].to_dict()

    @staticmethod
    def get_tokeninfo(token_address: ChecksumAddress,
                      catalog_address: Optional[ChecksumAddress] = None) -> Optional[dict]:
        token = CONTRACTS.get(token_address)
        if not token:
            return None
        if not catalog_address:
            if len(token.meta.get('catalogs', [])) == 0:  # not registered
                return None
            catalog_address = token.meta['catalogs'][-1]  # registered catalog at last
        assert catalog_address
        catalog = CONTRACTS.get(catalog_address)
        assert catalog
        return catalog.meta.get('tokens', {}).get(token_address, {})

    def fix_startblock(self) -> int:
        tmp = int(self.conf.get('start_block', 1))
        if tmp > 0:
            return tmp
        tmp += self.tdb_meta.latest
        return tmp if tmp > 0 else 1

    def apply_tx(self, tx0):
        function = tx0.get('function')
        if not function:
            return
        status = tx0.get('x_receipt_status', 0)
        if status != 1:  # ignore reverted transaction
            return
        if function == '(deploy)':
            DEPLOYERS[tx0['deployed_address']] = tx0['from']
            return
        address = tx0['to']
        if self.codesize.get(address) == 0:  # address is EOA
            return

        cname, _func = tx0['function'].split('.', 1)
        contract = CONTRACTS.get(address)
        if not contract:
            contract = CONTRACT_CLASSES.get(cname)(address)
        contract.update(tx0)

    def run(self):
        if not self.tdb_dec:
            raise Exception('ReadonlyMode')

        print_blocknum = bool(self.conf.get('print_blocknum', True))
        exit_on_head = bool(self.conf.get('exit_on_head', False))
        ext_lf = '\n' if print_blocknum else ''
        block = self.fix_startblock()

        self.tdb_dec.open(readonly=True)  # start with keep-alive mode
        self.tdb_meta.open(readonly=False)

        try:
            for block in self.tdb_dec.stored_blocks(minimum=block):
                print(f'\r{block}' if print_blocknum else '', end='', file=sys.stderr)
                for tx0 in self.tdb_dec.load(block, None):
                    self.apply_tx(tx0)
        except KeyboardInterrupt:
            self._save_meta()
            self.tdb_meta.update_latest(block - 1)
            print(f'{ext_lf}metadata_manager interrupted at block: {block}')
            return

        self.tdb_dec.close()  # switch out from keep-alive mode
        self.tdb_meta.close()

        block += 1
        while True:
            try:
                print(f'\r{block}' if print_blocknum else '', end='', file=sys.stderr)
                for tx0 in self.tdb_dec.load(block, None):
                    self.apply_tx(tx0)
                block += 1
                continue
            except KeyboardInterrupt:
                self._save_meta()
                self.tdb_meta.update_latest(block - 1)
                print(f'{ext_lf}metadata_manager interrupted at block: {block}')
                return
            except BlockNotFound:
                if exit_on_head:
                    self._save_meta()
                    self.tdb_meta.update_latest(block - 1)
                    print(f'{ext_lf}metadata_manager stopped at the head: {block}')
                    return
            try:
                self._save_meta()
                self.tdb_meta.update_latest(block - 1)
                sleep(1)
            except KeyboardInterrupt:
                print(f'{ext_lf}metadata_manager interrupted at block: {block}')
                return
        print(f'{ext_lf}metadata_manager stopped by error at block: {block}')


def main(args):
    meta_mgr = MetadataManager(args.config)
    meta_mgr.run()


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
