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

from __future__ import annotations

import inspect
import json
import os
from time import sleep
from typing import ClassVar, Dict, Optional

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.contract import Contract as Web3Contract

from metemcyber.core.bc.account import Account
from metemcyber.core.logger import get_logger

LOGGER = get_logger(name='contract', file_prefix='core.bc')
MINIMAL_CONTRACT_ID = 'MetemcyberMinimal.sol:MetemcyberMinimal'
TX_RETRY_MAX = 10
TX_RETRY_DELAY_SEC = 2


def combined_json_path(contract_id: str) -> str:
    contract_src = contract_id.split(':')[0]
    src_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(src_dir, 'contracts_data',
                            os.path.splitext(contract_src)[0] + '.combined.json')
    return filepath


def retryable_contract(cls):
    def __retryable(func):
        def wrapper(*args, **kwargs):
            for cnt in range(TX_RETRY_MAX):
                try:
                    return func(*args, **kwargs)
                except Exception as err:
                    LOGGER.exception(err)
                    sleep(TX_RETRY_DELAY_SEC)
                    LOGGER.warning(f'retrying:{cnt}')
                    continue
            raise Exception(f'Transaction retry count exceeds max({TX_RETRY_MAX}).')
        return wrapper

    # exclude methods defined in baseclass.
    excludes = [x[0] for x in inspect.getmembers(Contract)]
    for name, func in inspect.getmembers(cls):
        if name in excludes:
            continue
        if callable(getattr(cls, name)):
            setattr(cls, name, __retryable(func))
    return cls


class Contract():
    #                    contract_id: {address|placeholder: data}
    __deployed_libs: ClassVar[Dict[str, Dict[str, str]]] = {}
    __minimal_interface: ClassVar[Dict[str, str]] = {}
    #                              version: abi|bin: loaded data from combined json
    contract_interface: ClassVar[Dict[int, Dict[str, str]]] = {}  # overridden by sub class
    contract_id: ClassVar[Optional[str]] = None  # overridden by subclass
    _latest_version: ClassVar[int] = -1  # overridden by subclass

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
        self.version: int = -1

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

    @classmethod
    def latest_version(cls):
        # currently, there's no way to figure out the latest version. it's ok, maybe.
        return cls._latest_version

    def new(self, *args, **kwargs):
        # pylint: disable=protected-access
        address = self.__class__.__deploy(self.account, *args, **kwargs)
        return self.get(address, id_check=False)

    def get(self, address: ChecksumAddress, id_check: bool = True):
        assert address
        if not Web3.isChecksumAddress(address):
            raise Exception('Invalid address: {}'.format(address))
        if not id_check:  # the case called from new()
            latest = self.__class__.latest_version()
            # pylint: disable=protected-access
            self.__class__.__load(latest)
            self._contract = self.web3.eth.contract(
                address=address, abi=self.__class__.contract_interface[latest]['abi'])
            return self

        minimal = self.web3.eth.contract(
            address=address, abi=self.__minimal_abi())
        try:
            tmp_id = minimal.functions.contractId().call()
        except Exception:
            tmp_id = 'unknown type of address'
        if tmp_id != self.__class__.contract_id:
            tmp_id = tmp_id.split(':', 1)[1] if ':' in tmp_id else tmp_id
            raise Exception(f'Invalid address. {address} is {tmp_id}.')
        self.version = minimal.functions.contractVersion().call()
        # pylint: disable=protected-access
        self.__class__.__load(self.version)
        self._contract = self.web3.eth.contract(
            address=address, abi=self.__class__.contract_interface[self.version]['abi'])
        return self

    @classmethod
    def register_library(cls, address, placeholder=''):
        #   for detail of placeholder, see below.
        #   https://solidity.readthedocs.io/en/latest/using-the-compiler.html
        assert address
        assert cls.contract_id
        if cls.contract_id in Contract.__deployed_libs.keys():
            raise Exception('already registered')
        if not placeholder:
            keccak = Web3.keccak(text=cls.contract_id).hex()[2:]  # cut 0x
            placeholder = '__$' + keccak[:34] + '$__'
        Contract.__deployed_libs[cls.contract_id] = {
            'address': address, 'placeholder': placeholder}
        LOGGER.debug(Contract.__deployed_libs)
        return placeholder

    @staticmethod
    def __minimal_abi() -> str:
        if not Contract.__minimal_interface:
            minimal_file = combined_json_path(MINIMAL_CONTRACT_ID)
            with open(minimal_file, 'r') as fin:
                meta_str = json.loads(fin.read())['contracts'][MINIMAL_CONTRACT_ID]['metadata']
            Contract.__minimal_interface['abi'] = json.loads(meta_str)['output']['abi']
            # omit bytecode
        return Contract.__minimal_interface['abi']

    @classmethod
    def __load(cls, version: int):
        if not cls.contract_id:
            raise Exception('contract_id is not defined: {}'.format(cls))
        if cls.contract_interface.get(version):
            return

        contract_interface = {}
        try:
            combined_file = combined_json_path(cls.contract_id) + (
                '' if version < 0 else f'-{version}')  # no suffix for latest
            with open(combined_file, 'r') as fin:
                combined_json = json.loads(fin.read())['contracts'][cls.contract_id]

            # Metadata (json nested in json) の追加
            contract_metadata = json.loads(combined_json['metadata'])
            contract_interface['abi'] = contract_metadata['output']['abi']

            # バイナリデータの追加
            bytecode = combined_json['bin']
            for lib in Contract.__deployed_libs.values():
                # Oops, link_code@solcx does not work well...
                # WORKAROUND: replace placeholder with address manually.
                bytecode = bytecode.replace(
                    lib['placeholder'], lib['address'][2:])  # cut 0x
            contract_interface['bin'] = bytecode

        except Exception as err:
            LOGGER.exception(err)
            raise Exception(
                f'Failed loading contract: {cls.contract_id} '
                f'version {"latest" if version < 0 else version}') from err
        cls.contract_interface[version] = contract_interface

    @classmethod
    def __deploy(cls, account: Account, *args, **kwargs):
        # コントラクトのチェーンへのデプロイ
        latest = cls.latest_version()
        if not cls.contract_interface.get(latest):
            cls.__load(latest)

        LOGGER.debug('deploying %s with args=%s, kwargs=%s',
                     cls.__name__, args, kwargs)

        # constructorに引数が必要な場合は指定
        if args or kwargs:
            func = account.web3.eth.contract(
                abi=cls.contract_interface[latest]['abi'],
                bytecode=cls.contract_interface[latest]['bin']).\
                constructor(*args, **kwargs)
        else:
            func = account.web3.eth.contract(
                abi=cls.contract_interface[latest]['abi'],
                bytecode=cls.contract_interface[latest]['bin']).\
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
