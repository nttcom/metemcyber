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

from typing import ClassVar, Dict

from metemcyber.core.bc.contract import Contract, retryable_contract


@retryable_contract
class CTIBroker(Contract):
    contract_interface: ClassVar[Dict[int, Dict[str, str]]] = {}
    contract_id: ClassVar[str] = 'CTIBroker.sol:CTIBroker'

    def consign_token(self, catalog, token, amount):
        self.log_trace()
        func = self.contract.functions.consignToken(catalog, token, amount)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('consignToken', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('consignToken: transaction failed')
        self.log_success()

    def takeback_token(self, catalog, token, amount):
        self.log_trace()
        func = self.contract.functions.takebackToken(catalog, token, amount)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('takebackToken', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('takebackToken: transaction failed')
        self.log_success()

    def buy_token(self, catalog, token, wei, allow_cheaper=False):
        self.log_trace()
        func = self.contract.functions.buyToken(catalog, token, allow_cheaper)
        tx_hash = func.transact({'value': wei})
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('buyToken', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('buyToken: transaction failed')
        self.log_success()

    def get_amounts(self, catalog, tokens):
        self.log_trace()
        func = self.contract.functions.getAmounts(catalog, tokens)
        return func.call()
