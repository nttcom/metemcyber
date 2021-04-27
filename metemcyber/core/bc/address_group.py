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

from typing import ClassVar, Dict, List

from eth_typing import ChecksumAddress

from metemcyber.core.bc.contract import Contract, retryable_contract


@retryable_contract
class AddressGroup(Contract):
    contract_interface: ClassVar[Dict[int, Dict[str, str]]] = {}
    contract_id: ClassVar[str] = 'AddressGroup.sol:AddressGroup'

    @property
    def owner(self) -> ChecksumAddress:
        self.log_trace()
        func = self.contract.functions.owner()
        return func.call()

    @property
    def members(self) -> List[ChecksumAddress]:
        self.log_trace()
        func = self.contract.functions.listMembers()
        return func.call()

    def is_member(self, user: ChecksumAddress) -> bool:
        self.log_trace()
        func = self.contract.functions.isMember(user)
        return func.call()

    def add(self, user: ChecksumAddress) -> None:
        self.log_trace()
        func = self.contract.functions.add(user)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: add')
        self.log_success()

    def remove(self, user: ChecksumAddress) -> None:
        self.log_trace()
        func = self.contract.functions.remove(user)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: remove')
        self.log_success()

    def clear(self) -> None:
        self.log_trace()
        func = self.contract.functions.clear()
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: clear')
        self.log_success()
