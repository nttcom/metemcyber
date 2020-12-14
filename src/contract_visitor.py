#
#    Copyright 2020, NTT Communications Corp.
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

from abc import ABCMeta, abstractmethod
import copy
import logging
import glob
import json
import os
from solcx import compile_files #, link_code
from web3 import Web3

LOGGER = logging.getLogger('common')
GASLOG = logging.getLogger('gaslog')


class Visitor(metaclass=ABCMeta):
    @abstractmethod
    def visit(self, contracts):
        pass


class ContractVisitor(Visitor):

    contract_interface = dict()  # shold be overridden by sub class
    pool = dict()  # shold be overridden by sub class
    deployed_libs = dict() # {name: {address:x, placeholder:x}}

    def __init__(self):
        self.contracts = None
        self.contract = None
        self.contract_address = None
        self.contract_id = None
        self.contract_src = None

    def visit(self, contracts):
        self.contracts = contracts
        return self

    def register_library(self, address, placeholder=''):
        # WORKAROUND:
        #   solcx.link_code() does not work well.
        #   then replace placeholder with address manually, at loading..
        #   for detail of placeholder, see below.
        #   https://solidity.readthedocs.io/en/latest/using-the-compiler.html
        assert address
        assert self.contract_id
        if self.contract_id in self.deployed_libs.keys():
            raise Exception('already registered')
        if not placeholder:
            keccak = Web3.keccak(text=self.contract_id).hex()[2:] # cut 0x
            placeholder = '__$' + keccak[:34] + '$__'
        self.deployed_libs[self.contract_id] = {
            'address': address, 'placeholder': placeholder}
        LOGGER.info(self.deployed_libs)
        return placeholder

    def new(self, *args, **kwargs):
        if not self.contract_id:
            raise Exception('contract_id is not defined: {}'.format(self))
        if self.contract_id in self.deployed_libs.keys():
            # already registered library. (FAILSAFE: may not called twice)
            return self.get(self.deployed_libs[self.contract_id]['address'])
        if not self.__class__.contract_interface:
            self.__load()
        address = self.__deploy(*args, **kwargs)
        self.add(address)
        return self

    def get(self, address):
        if address not in self.pool.keys():
            self.add(address)
        self.contract_address = address
        self.contract = self.pool[address]
        return self

    def add(self, address):
        ## TODO: should check specified address is valid?
        if address in self.pool.keys():
            raise Exception(
                'already exists with same address: {}'.format(address))

        # インターフェースがない場合はビルド
        if not self.__class__.contract_interface:
            self.__load()

        # HACK: 最新ビルドを再利用（デフォルト以外を利用する場合は要検討）
        contract_interface = copy.deepcopy(self.__class__.contract_interface)

        self.contract_address = address
        contract = self.contracts.web3.eth.contract(
            address=address, abi=contract_interface['abi'])

        self.contract = contract
        self.pool[address] = contract

    def __load(self):
        if not self.contract_id:
            raise Exception('contract_id is not defined: {}'.format(self))
        if self.__class__.contract_interface:
            return

        # contract_id is "<SourceFilename>:<ContractName>"
        self.contract_src = self.contract_id.split(':')[0]
        contract_basename = os.path.splitext(self.contract_src)[0]
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
                    json.loads(fin.read())['contracts'][self.contract_id]

            # Metadata (json nested in json) の追加
            contract_metadata = json.loads(combined_json['metadata'])
            contract_interface['abi'] = contract_metadata['output']['abi']

            # バイナリデータの追加
            bytecode = combined_json['bin']
            for lib in self.deployed_libs.values():
                ## Oops, link_code does not work well...
                #bytecode = link_code(bytecode, {lib: self.deployed_libs[lib]})
                ## WORKAROUND: replace with address manually.
                bytecode = bytecode.replace(
                    lib['placeholder'], lib['address'][2:])  # cut 0x
            contract_interface['bin'] = bytecode

        except (FileNotFoundError, KeyError) as err:
            raise Exception(
                'Contract data load failed: {}'.format(self.contract_src)) \
                from err
        self.__class__.contract_interface = contract_interface

    def __build(self):
        if not self.contract_src:
            raise Exception('contract_src is not defined: {}'.format(self))
        if self.__class__.contract_interface:
            return True

        work_dir = os.path.dirname(os.path.abspath(__file__))
        # Solidity ソースファイルを格納するディレクトリを追加
        contracts_dir = os.path.join(work_dir, 'contracts')
        # openzeppelinのディレクトリを追加
        openzeppelin_dir = os.path.join(contracts_dir, 'node_modules',
                                        '@openzeppelin')

        lib_dirs = glob.glob(os.path.join(openzeppelin_dir, '**' + os.sep),
                             recursive=True)

        # 独自コントラクトのパスを追加
        src = [os.path.join(contracts_dir, self.contract_src)]

        # solidityソースファイルのコンパイル
        compiled_sol = compile_files(
            source_files=src,
            optimize=True,
            allow_paths=','.join(lib_dirs),
            import_remappings=["@openzeppelin={}".format(openzeppelin_dir)])

        # インタフェースの更新
        for contract_id, contract_interface in compiled_sol.items():
            # print('Setup constract:', contract_id)
            if self.contract_src in contract_id:
                self.contract_id = contract_id
                self.__class__.contract_interface = contract_interface
                return True
        raise Exception('Contract build failed: {}'.format(self.contract_src))

    def __deploy(self, *args, **kwargs):
        # コントラクトのチェーンへのデプロイ
        if not self.contracts.web3:
            raise Exception('not yet initialized with web3')
        if not self.__class__.contract_interface:
            raise Exception('not yet built')

        # constructorに引数が必要な場合は指定
        if args or kwargs:
            func = self.contracts.web3.eth.contract(
                abi=self.__class__.contract_interface['abi'],
                bytecode=self.__class__.contract_interface['bin']).\
                    constructor(*args, **kwargs)
        else:
            func = self.contracts.web3.eth.contract(
                abi=self.__class__.contract_interface['abi'],
                bytecode=self.__class__.contract_interface['bin']).\
                    constructor()

        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('deploy', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Contract deploy failed: {}'.format(
                self.contract_src))

        return tx_receipt['contractAddress']

    def event_filter(self, event_name, **kwargs):
        event = getattr(self.contract.events, event_name)
        return event.createFilter(**kwargs)

    def gaslog(self, func, tx_receipt):
        GASLOG.info(
            '%s.%s: gasUsed=%d', self.__class__.__name__, func,
            tx_receipt['gasUsed'])
