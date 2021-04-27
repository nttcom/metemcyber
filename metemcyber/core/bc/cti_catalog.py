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

from typing import ClassVar, Dict, List, Tuple, cast
from uuid import UUID

from eth_typing import ChecksumAddress

from metemcyber.core.bc.address_group import AddressGroup
from metemcyber.core.bc.contract import Contract, retryable_contract
from metemcyber.core.bc.util import ADDRESS0


@retryable_contract
class CTICatalog(Contract):
    contract_interface: ClassVar[Dict[int, Dict[str, str]]] = {}
    contract_id: ClassVar[str] = 'CTICatalog.sol:CTICatalog'

    def get_owner(self):
        if self.version == 0:
            func = self.contract.functions.getOwner()
        else:
            func = self.contract.functions.owner()
        return func.call()

    def publish_cti(self, producer_address: ChecksumAddress,
                    token_address: ChecksumAddress) -> None:
        self.log_trace()
        func = self.contract.functions.publishCti(
            producer_address, token_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('publishCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: publishCti')
        self.log_success()

    def register_cti(self, token_address: ChecksumAddress, uuid: UUID, title: str, price: int,
                     operator: str) -> None:
        self.log_trace()
        func = self.contract.functions.registerCti(
            token_address, str(uuid), title, price, operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('registerCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: registerCti')
        self.log_success()

    def modify_cti(self, token_address: ChecksumAddress, uuid: UUID, title: str, price: int,
                   operator: str) -> None:
        self.log_trace()
        func = self.contract.functions.modifyCti(
            token_address, str(uuid), title, price, operator)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('modifyCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: modifyCti')
        self.log_success()

    def unregister_cti(self, token_address: ChecksumAddress):
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

    def get_cti_info(self, token_address: ChecksumAddress) -> Tuple[
            int, ChecksumAddress, UUID, str, int, str, dict]:
        self.log_trace()
        func = self.contract.functions.getCtiInfo(token_address)
        token_id, owner, uuid, title, price, operator, likecount = func.call()
        return token_id, cast(ChecksumAddress, owner), UUID(uuid), title, price, operator, likecount

    def like_cti(self, token_address: ChecksumAddress) -> None:
        self.log_trace()
        func = self.contract.functions.likeCti(token_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('likeCti', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: likeCti')
        self.log_success()

    def get_like_event(self, search_blocks: int = 1000) -> list:
        self.log_trace()
        # 最大search_blocks数だけ、CtiLiked eventを取得して返す
        from_block = max(
            self.web3.eth.blockNumber - search_blocks + 1, 0)
        # filterの作成
        event_filter = self.event_filter('CtiLiked', fromBlock=from_block)
        # filterに合致するeventの取得
        event_logs = event_filter.get_all_entries()
        return event_logs

    @property
    def members(self) -> ChecksumAddress:
        self.log_trace()
        assert self.version > 0
        return self.contract.functions.members().call()

    def is_private(self) -> bool:
        self.log_trace()
        if self.version > 0:
            return self.members != ADDRESS0
        func = self.contract.functions.isPrivate()
        return func.call()

    def set_private(self) -> None:
        self.log_trace()
        if self.is_private():
            return
        if self.version == 0:
            func = self.contract.functions.setPrivate()
            func_str = 'setPrivate'
        else:
            members = AddressGroup(self.account).new()
            func = self.contract.functions.setMembers(members.address)
            func_str = 'setMembers'
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setPrivate', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError(f'Transaction failed: {func_str}')
        self.log_success()

    def set_public(self) -> None:
        self.log_trace()
        if not self.is_private():
            return
        if self.version == 0:
            func = self.contract.functions.setPublic()
            func_str = 'setPublic'
        else:
            func = self.contract.functions.setMembers(ADDRESS0)
            func_str = 'setMembers'
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('setPublic', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError(f'Transaction failed: {func_str}')
        self.log_success()

    def authorize_user(self, eoa_address: ChecksumAddress) -> None:
        self.log_trace()
        if self.version > 0:
            assert self.is_private()
            AddressGroup(self.account).get(self.members).add(eoa_address)
            return
        func = self.contract.functions.authorizeUser(eoa_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('authorizeUser', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: authorizeUser')
        self.log_success()

    def revoke_user(self, eoa_address: ChecksumAddress) -> None:
        self.log_trace()
        if self.version > 0:
            assert self.is_private()
            AddressGroup(self.account).get(self.members).remove(eoa_address)
            return
        func = self.contract.functions.revokeUser(eoa_address)
        tx_hash = func.transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        self.gaslog('revokeUser', tx_receipt)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: revokeUser')
        self.log_success()

    def show_authorized_users(self) -> List[ChecksumAddress]:
        self.log_trace()
        if self.version > 0:
            assert self.is_private()
            return AddressGroup(self.account).get(self.members).members
        func = self.contract.functions.showAuthorizedUsers()
        return func.call()
