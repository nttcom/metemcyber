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

import inspect
import json
import os
from typing import Dict, Optional

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.contract import Contract as Web3Contract

from ..logger import get_logger
from .account import Account

LOGGER = get_logger(name='contract', file_prefix='core.bc')


class Contract():
    #                   library_address  placeholder
    deployed_libs: Dict[ChecksumAddress, str] = {}
    #                    abi|bin  loaded data from combined json
    contract_interface: Dict[str, str] = {}  # overridden by sub class
    contract_id: Optional[str] = None  # overridden by subclass

    def log_trace(self):
        try:
            cname = self.__class__.__name__
            frame = inspect.stack()[1][0]
            func = inspect.getframeinfo(frame).function
            args = {key: val for key, val
                    in inspect.getargvalues(frame).locals.items()
                    if key != 'self'}
            LOGGER.debug('%s(%s).%s%s', cname, self.address, func, args)
        finally:
            pass

    def log_success(self):
        try:
            cname = self.__class__.__name__
            frame = inspect.stack()[1][0]
            func = inspect.getframeinfo(frame).function
            LOGGER.debug('%s(%s).%s: succeeded', cname, self.address, func)
        finally:
            pass

    def __init__(self, account: Account):
        self.account: Account = account
        self._contract: Optional[Web3Contract] = None  # initialized by get()

    @property
    def web3(self) -> Web3:
        return self.account.web3

    @property
    def contract(self) -> Web3Contract:
        assert self._contract
        return self._contract

    @property
    def address(self):
        return self._contract.address if self._contract else None

    def new(self, *args, **kwargs):
        # pylint: disable=protected-access
        address = self.__class__.__deploy(self.account, *args, **kwargs)
        return self.get(address)

    def get(self, address: ChecksumAddress):
        assert address
        if not Web3.isChecksumAddress(address):
            raise Exception('Invalid address: {}'.format(address))
        # pylint: disable=protected-access
        self.__class__.__load()
        self._contract = self.web3.eth.contract(
            address=address, abi=self.__class__.contract_interface['abi'])
        return self

    @classmethod
    def register_library(cls, address, placeholder=''):
        #   for detail of placeholder, see below.
        #   https://solidity.readthedocs.io/en/latest/using-the-compiler.html
        assert address
        assert cls.contract_id
        if cls.contract_id in Contract.deployed_libs.keys():
            raise Exception('already registered')
        if not placeholder:
            keccak = Web3.keccak(text=cls.contract_id).hex()[2:]  # cut 0x
            placeholder = '__$' + keccak[:34] + '$__'
        Contract.deployed_libs[cls.contract_id] = {
            'address': address, 'placeholder': placeholder}
        LOGGER.debug(Contract.deployed_libs)
        return placeholder

    @classmethod
    def __load(cls):
        if not cls.contract_id:
            raise Exception('contract_id is not defined: {}'.format(cls))
        if cls.contract_interface:
            return

        # contract_id is "<SourceFilename>:<ContractName>"
        contract_src = cls.contract_id.split(':')[0]
        contract_basename = os.path.splitext(contract_src)[0]
        contract_interface = dict()
        try:
            # contractsのcombined.jsonが配置されているパス
            work_dir = os.path.dirname(os.path.abspath(__file__))
            contractsdata_dir = os.path.join(work_dir, 'contracts_data')

            # combined.json should be generated with
            #   % solc --combined-json bin,metadata xxx.sol \
            #     > contracts_data/xxx.combined.json
            combined_file = os.path.join(
                contractsdata_dir, contract_basename + '.combined.json')
            with open(combined_file, 'r') as fin:
                combined_json = \
                    json.loads(fin.read())['contracts'][cls.contract_id]

            # Metadata (json nested in json) の追加
            contract_metadata = json.loads(combined_json['metadata'])
            contract_interface['abi'] = contract_metadata['output']['abi']

            # バイナリデータの追加
            bytecode = combined_json['bin']
            for lib in Contract.deployed_libs.values():
                # Oops, link_code@solcx does not work well...
                # WORKAROUND: replace placeholder with address manually.
                bytecode = bytecode.replace(
                    lib['placeholder'], lib['address'][2:])  # cut 0x
            contract_interface['bin'] = bytecode

        except (FileNotFoundError, KeyError) as err:
            raise Exception(
                'Contract data load failed: {}'.format(cls.contract_id)) from err
        cls.contract_interface = contract_interface

    @classmethod
    def __deploy(cls, account: Account, *args, **kwargs):
        # コントラクトのチェーンへのデプロイ
        if not cls.contract_interface:
            cls.__load()

        LOGGER.debug('deploying %s with args=%s, kwargs=%s',
                     cls.__name__, args, kwargs)

        # constructorに引数が必要な場合は指定
        if args or kwargs:
            func = account.web3.eth.contract(
                abi=cls.contract_interface['abi'],
                bytecode=cls.contract_interface['bin']).\
                constructor(*args, **kwargs)
        else:
            func = account.web3.eth.contract(
                abi=cls.contract_interface['abi'],
                bytecode=cls.contract_interface['bin']).\
                constructor()

        tx_hash = func.transact()
        tx_receipt = account.web3.eth.waitForTransactionReceipt(tx_hash)
        cls.gaslog('deploy', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError(
                'Contract deploy failed: {}'.format(cls.contract_id))

        LOGGER.info('deployed %s on address: %s',
                    cls.__name__, tx_receipt['contractAddress'])
        return tx_receipt['contractAddress']

    def event_filter(self, event_name, **kwargs):
        event = getattr(self.contract.events, event_name)
        return event.createFilter(**kwargs)

    @classmethod
    def gaslog(cls, func, tx_receipt):
        LOGGER.debug(
            '%s.%s: gasUsed=%d', cls.__name__, func, tx_receipt['gasUsed'])
