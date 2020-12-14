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

import logging
from contract_visitor import ContractVisitor

LOGGER = logging.getLogger('common')

class CTIOperator(ContractVisitor):

    contract_interface = dict()
    pool = dict()

    def __init__(self):
        super().__init__()
        self.contract_id = 'CTIOperator.sol:CTIOperator'

    def history(self, token_address, limit, offset=0):
        func = self.contract.functions.history(token_address, limit, offset)
        return func.call()

    def set_recipient(self):
        func = self.contract.functions.recipientFor(self.contract_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('recipientFor', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: recipientFor')

    def register_recipient(self):
        func = self.contract.functions.registerRecipient(self.contract_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('registerRecipient', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: registerRecipient')

    def register_tokens(self, token_addresses):
        func = self.contract.functions.register(token_addresses)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('register', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: register')
        LOGGER.info('register succeeded: %s', token_addresses)

    def unregister_tokens(self, token_addresses):
        func = self.contract.functions.unregister(token_addresses)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('unregister', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: unregister')
        LOGGER.info('unregister succeeded: %s', token_addresses)

    def accept_task(self, task_id):
        func = self.contract.functions.accepted(task_id)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('accepted', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: accepted')
        LOGGER.info('accept_task succeeded: %s', task_id)

    def finish_task(self, task_id, data=''):
        func = self.contract.functions.finish(task_id, data)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('finish', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: finish')
        LOGGER.info('finish_task succeeded: %s', task_id)

    def cancel_challenge(self, task_id):
        func = self.contract.functions.cancelTask(task_id)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('cancelTask', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: cancelTask')

    def reemit_pending_tasks(self):
        func = self.contract.functions.reemitPendingTasks()
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('reemitPendingTasks', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: reemitPendingTasks')
