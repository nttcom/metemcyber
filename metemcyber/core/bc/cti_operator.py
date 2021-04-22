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

from typing import ClassVar, Dict, List, Optional, Tuple

from eth_typing import ChecksumAddress

from metemcyber.core.bc.contract import Contract, retryable_contract
from metemcyber.core.bc.util import ADDRESS0


@retryable_contract
class CTIOperator(Contract):
    contract_interface: ClassVar[Dict[int, Dict[str, str]]] = {}
    contract_id: ClassVar[str] = 'CTIOperator.sol:CTIOperator'

    def history(self, token_address: ChecksumAddress, seeker_address: Optional[ChecksumAddress],
                limit: int, offset: int = 0
                #               task_id, token,       solver,          seeker_address,  state
                ) -> List[Tuple[int, ChecksumAddress, ChecksumAddress, ChecksumAddress, int]]:
        self.log_trace()
        if self.version < 1:
            func = self.contract.functions.history(token_address, limit, offset)
        else:
            if seeker_address is None:
                seeker_address = ADDRESS0
            func = self.contract.functions.history(token_address, seeker_address, limit, offset)
        return func.call()

    def set_recipient(self):
        self.log_trace()
        func = self.contract.functions.recipientFor(self.address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('recipientFor', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: recipientFor')
        self.log_success()

    def register_recipient(self):
        self.log_trace()
        func = self.contract.functions.registerRecipient(self.address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('registerRecipient', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: registerRecipient')
        self.log_success()

    def register_tokens(self, token_addresses):
        self.log_trace()
        func = self.contract.functions.register(token_addresses)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('register', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: register')
        self.log_success()

    def unregister_tokens(self, token_addresses):
        self.log_trace()
        func = self.contract.functions.unregister(token_addresses)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('unregister', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: unregister')
        self.log_success()

    def accept_task(self, task_id):
        self.log_trace()
        func = self.contract.functions.accepted(task_id)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('accepted', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: accepted')
        self.log_success()

    def finish_task(self, task_id, data=''):
        self.log_trace()
        func = self.contract.functions.finish(task_id, data)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('finish', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: finish')
        self.log_success()

    def cancel_challenge(self, task_id):
        self.log_trace()
        func = self.contract.functions.cancelTask(task_id)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('cancelTask', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: cancelTask')
        self.log_success()

    def reemit_pending_tasks(self, tokens):
        self.log_trace()
        func = self.contract.functions.reemitPendingTasks(tokens)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('reemitPendingTasks', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: reemitPendingTasks')
        self.log_success()

    def check_registered(self, token_addresses):
        self.log_trace()
        func = self.contract.functions.checkRegistered(token_addresses)
        return func.call()
