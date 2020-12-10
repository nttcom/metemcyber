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


class CTIBroker(ContractVisitor):

    contract_interface = dict()
    pool = dict()

    def __init__(self):
        super().__init__()
        self.contract_id = 'CTIBroker.sol:CTIBroker'

    def consign_token(self, catalog, token, amount):
        func = self.contract.functions.consignToken(catalog, token, amount)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('consignToken', tx_receipt)
        if tx_receipt['status'] != 1:
            LOGGER.error('consignToken: transaction failed')
            raise Exception('consignToken: transaction failed')

    def takeback_token(self, catalog, token, amount):
        func = self.contract.functions.takebackToken(catalog, token, amount)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('takebackToken', tx_receipt)
        if tx_receipt['status'] != 1:
            LOGGER.error('takebackToken: transaction failed')
            raise Exception('takebackToken: transaction failed')

    def buy_token(self, catalog, token, wei, allow_cheaper=False):
        func = self.contract.functions.buyToken(catalog, token, allow_cheaper)
        tx_hash = func.transact({'value': wei})
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('buyToken', tx_receipt)
        if tx_receipt['status'] != 1:
            LOGGER.error('buyToken: transaction failed')
            raise Exception('buyToken: transaction failed')

    def get_amounts(self, catalog, tokens):
        func = self.contract.functions.getAmounts(catalog, tokens)
        return func.call()
