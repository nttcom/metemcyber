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

from typing import ClassVar, Dict, List, Tuple

from eth_typing import ChecksumAddress
from web3 import Web3

from metemcyber.core.bc.contract import Contract, ContractVersionError, retryable_contract


@retryable_contract
class CTIToken(Contract):
    contract_interface: ClassVar[Dict[int, Dict[str, str]]] = {}
    contract_id: ClassVar[str] = 'CTIToken.sol:CTIToken'

    @property
    def publisher(self) -> ChecksumAddress:
        self.log_trace()
        func = self.contract.functions.publisher()
        return func.call()

    def balance_of(self, account_id):
        self.log_trace()
        func = self.contract.functions.balanceOf(account_id)
        return func.call()

    def mint(self, dest: ChecksumAddress, amount: int,
             user_data: str = '', operator_data: str = ''):
        self.log_trace()
        bdata_user = Web3.toBytes(text=user_data)
        bdata_operator = Web3.toBytes(text=operator_data)
        func = self.contract.functions.mint(dest, amount, bdata_user, bdata_operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: mint')
        self.log_success()

    def send(self, dest, amount=1, data=''):
        self.log_trace()
        bdata = Web3.toBytes(text=data)
        func = self.contract.functions.send(dest, amount, bdata)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('send', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: send')
        self.log_success()

    def burn(self, amount, data=''):
        self.log_trace()
        bdata = Web3.toBytes(text=data)
        func = self.contract.functions.burn(amount, bdata)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('burn', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: burn')
        self.log_success()

    def authorize_operator(self, operator):
        self.log_trace()
        func = self.contract.functions.authorizeOperator(operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('authorizeOperator', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: authorizeOperator')
        self.log_success()

    def revoke_operator(self, operator):
        self.log_trace()
        func = self.contract.functions.revokeOperator(operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('revokeOperator', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: revokeOperator')
        self.log_success()

    def is_operator(self, operator: ChecksumAddress, token_holder: ChecksumAddress) -> bool:
        self.log_trace()
        func = self.contract.functions.isOperatorFor(operator, token_holder)
        return func.call()

    @property
    def editable(self) -> bool:
        if self.version < 1:
            raise ContractVersionError('Not supported (too old contract version)')
        self.log_trace()
        func = self.contract.functions.editable()
        return func.call()

    def set_editable(self, editable: bool):
        if self.version < 1:
            raise ContractVersionError('Not supported (too old contract version)')
        self.log_trace()
        func = self.contract.functions.setEditable(editable)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setEditable', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: setEditable')
        self.log_success()

    def add_candidates(self, candidates: List[str]):
        if self.version < 1:
            raise ContractVersionError('Not supported (too old contract version)')
        self.log_trace()
        func = self.contract.functions.addCandidates(candidates)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('addCandidates', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: addCandidates')
        self.log_success()

    def remove_candidates(self, indexes: List[int]):
        if self.version < 1:
            raise ContractVersionError('Not supported (too old contract version)')
        self.log_trace()
        func = self.contract.functions.removeCandidates(indexes)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('removeCandidates', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: removeCandidates')
        self.log_success()

    def list_candidates(self) -> List[Tuple[int, int, str]]:  # [(index, score, desc), ...]
        if self.version < 1:
            raise ContractVersionError('Not supported (too old contract version)')
        self.log_trace()
        func = self.contract.functions.listCandidates()
        return func.call()

    def vote(self, index: int, amount: int):
        if self.version < 1:
            raise ContractVersionError('Not supported (too old contract version)')
        self.log_trace()
        func = self.contract.functions.vote(index, amount)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('vote', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: vote')
        self.log_success()
