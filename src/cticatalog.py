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


class CTICatalog(ContractVisitor):

    contract_interface = dict()
    pool = dict()

    def __init__(self):
        super().__init__()
        self.contract_id = 'CTICatalog.sol:CTICatalog'

    def get_owner(self):
        func = self.contract.functions.getOwner()
        return func.call()

    def publish_cti(self, producer_address, token_address):
        func = self.contract.functions.publishCti(
            producer_address, token_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('publishCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: publishCti')

    def register_cti(self, token_address, uuid, title, price, operator):
        func = self.contract.functions.registerCti(
            token_address, uuid, title, price, operator)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('registerCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: registerCti')

    def modify_cti(self, token_address, uuid, title, price, operator):
        func = self.contract.functions.modifyCti(
            token_address, uuid, title, price, operator)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('modifyCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: modifyCti')

    def unregister_cti(self, token_address):
        func = self.contract.functions.unregisterCti(token_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('unregisterCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: unregisterCti')

    def list_token_uris(self):
        func = self.contract.functions.listTokenURIs()
        tokens = func.call()
        return [t for t in tokens if t != '']

    def get_cti_info(self, token_address):
        func = self.contract.functions.getCtiInfo(token_address)
        uuid, token_id, owner, title, price, operator, likecount = func.call()
        return uuid, token_id, owner, title, price, operator, likecount

    def like_cti(self, token_address):
        func = self.contract.functions.likeCti(token_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('likeCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: likeCti')

    def get_like_event(self, search_blocks=1000):
        # 最大search_blocks数だけ、CtiLiked eventを取得して返す
        from_block = max(
            self.contracts.web3.eth.blockNumber - search_blocks + 1, 0)
        # filterの作成
        event_filter = self.event_filter('CtiLiked', fromBlock=from_block)
        # filterに合致するeventの取得
        event_logs = event_filter.get_all_entries()
        return event_logs

    def is_private(self):
        func = self.contract.functions.isPrivate()
        return func.call()

    def set_private(self):
        func = self.contract.functions.setPrivate()
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setPrivate', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: setPrivate')

    def set_public(self):
        func = self.contract.functions.setPublic()
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setPublic', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: setPublic')

    def authorize_user(self, eoa_address):
        func = self.contract.functions.authorizeUser(eoa_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('authorizeUser', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: authorizeUser')

    def revoke_user(self, eoa_address):
        func = self.contract.functions.revokeUser(eoa_address)
        tx_hash = func.transact()
        tx_receipt = self.contracts.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('revokeUser', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: revokeUser')

    def show_authorized_users(self):
        func = self.contract.functions.showAuthorizedUsers()
        return func.call()
