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

from typing import Dict
from .contract import Contract


class CTICatalog(Contract):
    contract_interface: Dict[str, str] = {}
    contract_id = 'CTICatalog.sol:CTICatalog'

    def get_owner(self):
        func = self.contract.functions.getOwner()
        return func.call()

    def publish_cti(self, producer_address, token_address):
        self.log_trace()
        func = self.contract.functions.publishCti(
            producer_address, token_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('publishCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: publishCti')
        self.log_success()

    def register_cti(self, token_address, uuid, title, price, operator):
        self.log_trace()
        func = self.contract.functions.registerCti(
            token_address, uuid, title, price, operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('registerCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: registerCti')
        self.log_success()

    def modify_cti(self, token_address, uuid, title, price, operator):
        self.log_trace()
        func = self.contract.functions.modifyCti(
            token_address, uuid, title, price, operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('modifyCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: modifyCti')
        self.log_success()

    def unregister_cti(self, token_address):
        self.log_trace()
        func = self.contract.functions.unregisterCti(token_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('unregisterCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: unregisterCti')
        self.log_success()

    def list_token_uris(self):
        self.log_trace()
        func = self.contract.functions.listTokenURIs()
        tokens = func.call()
        return [t for t in tokens if t != '']

    def get_cti_info(self, token_address):
        self.log_trace()
        func = self.contract.functions.getCtiInfo(token_address)
        token_id, owner, uuid, title, price, operator, likecount = func.call()
        return token_id, owner, uuid, title, price, operator, likecount

    def like_cti(self, token_address):
        self.log_trace()
        func = self.contract.functions.likeCti(token_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('likeCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: likeCti')
        self.log_success()

    def get_like_event(self, search_blocks=1000):
        self.log_trace()
        # 最大search_blocks数だけ、CtiLiked eventを取得して返す
        from_block = max(
            self.web3.eth.blockNumber - search_blocks + 1, 0)
        # filterの作成
        event_filter = self.event_filter('CtiLiked', fromBlock=from_block)
        # filterに合致するeventの取得
        event_logs = event_filter.get_all_entries()
        return event_logs

    def is_private(self):
        self.log_trace()
        func = self.contract.functions.isPrivate()
        return func.call()

    def set_private(self):
        self.log_trace()
        func = self.contract.functions.setPrivate()
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setPrivate', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: setPrivate')
        self.log_success()

    def set_public(self):
        self.log_trace()
        func = self.contract.functions.setPublic()
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setPublic', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: setPublic')
        self.log_success()

    def authorize_user(self, eoa_address):
        self.log_trace()
        func = self.contract.functions.authorizeUser(eoa_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('authorizeUser', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: authorizeUser')
        self.log_success()

    def revoke_user(self, eoa_address):
        self.log_trace()
        func = self.contract.functions.revokeUser(eoa_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('revokeUser', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: revokeUser')
        self.log_success()

    def show_authorized_users(self):
        self.log_trace()
        func = self.contract.functions.showAuthorizedUsers()
        return func.call()
