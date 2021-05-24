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

from __future__ import annotations

from typing import Dict, List, Optional

from eth_typing import ChecksumAddress

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_token import CTIToken
from metemcyber.core.bc.util import ADDRESS0


class Token():
    #                token address         eoa address      balance
    tokens_map: Dict[ChecksumAddress, Dict[ChecksumAddress, int]] = {}

    def __init__(self, account: Account) -> None:
        self.account: Account = account
        self.address: Optional[ChecksumAddress] = None

    def get(self, address: ChecksumAddress) -> Token:
        self.address = address
        return self

    def new(self, initial_supply: int,
            default_operators: List[ChecksumAddress]) -> Token:
        cti_token = CTIToken(self.account).new(initial_supply, default_operators)
        return self.get(cti_token.address)

    def uncache(self, entire: bool = False) -> None:
        if entire:
            del Token.tokens_map
            Token.tokens_map = {}
        else:
            assert self.address
            if self.address in Token.tokens_map.keys():
                del Token.tokens_map[self.address]

    @property
    def publisher(self) -> ChecksumAddress:
        assert self.address
        return CTIToken(self.account).get(self.address).publisher

    def balance_of(self, target: ChecksumAddress) -> int:
        assert self.address
        if self.address not in Token.tokens_map.keys():
            Token.tokens_map[self.address] = {}
        if target not in Token.tokens_map[self.address].keys():
            cti_token = CTIToken(self.account).get(self.address)
            balance = cti_token.balance_of(target)
            Token.tokens_map[self.address][target] = balance
        return Token.tokens_map[self.address][target]

    def mint(self, amount: int, dest: Optional[ChecksumAddress] = None) -> None:
        assert self.address
        if dest in (None, ADDRESS0):
            dest = self.account.eoa
        cti_token = CTIToken(self.account).get(self.address)
        cti_token.mint(dest, amount)
        self.uncache()

    def send(self, dest: ChecksumAddress, amount: int, data: str = '') -> None:
        assert self.address
        cti_token = CTIToken(self.account).get(self.address)
        cti_token.send_token(dest, amount, data)
        self.uncache()

    def burn(self, amount: int, data: str = '') -> None:
        assert self.address
        cti_token = CTIToken(self.account).get(self.address)
        cti_token.burn_token(amount, data)
        self.uncache()
