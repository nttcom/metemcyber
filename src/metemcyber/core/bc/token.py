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

import inspect
from typing import Dict, List, Optional, Tuple

from eth_typing import ChecksumAddress

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_token import CTIToken
from metemcyber.core.bc.util import ADDRESS0


class Token():
    #                token address         eoa address      balance
    tokens_map: Dict[ChecksumAddress, Dict[ChecksumAddress, int]] = {}
    address: ChecksumAddress

    def __init__(self, account: Account) -> None:
        self.account: Account = account

    def get(self, address: ChecksumAddress) -> Token:
        self.address = address
        return self

    def new(self, initial_supply: int,
            default_operators: List[ChecksumAddress],
            anyone_editable: bool) -> Token:
        cti_token = CTIToken(self.account).new(initial_supply, default_operators, anyone_editable)
        return self.get(cti_token.address)

    def _passthrough(self, *args, **kwargs):
        assert self.address
        cti_token = CTIToken(self.account).get(self.address)
        finfo = inspect.getframeinfo(inspect.stack()[1][0])
        func = getattr(cti_token, finfo.function)
        if not callable(func):  # maybe a property
            return func
        return func(*args, **kwargs)

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
        return self._passthrough()

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

    def send(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)
        self.uncache()

    def burn(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)
        self.uncache()

    def is_operator(self, *args, **kwargs) -> bool:
        return self._passthrough(*args, **kwargs)

    def authorize_operator(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)

    def revoke_operator(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)

    def event_filter(self, *args, **kwargs):
        return self._passthrough(*args, **kwargs)

    @property
    def editable(self) -> bool:
        return self._passthrough()

    def set_editable(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)

    def add_candidates(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)

    def remove_candidates(self, *args, **kwargs):
        self._passthrough(*args, **kwargs)

    def list_candidates(self) -> List[Tuple[int, int, str]]:  # [(index, score, desc), ...]
        return self._passthrough()

    def vote(self, index: int, amount: int):
        if amount <= 0 or self.balance_of(self.account.eoa) < amount:
            raise Exception(f'Invalid amount: {amount}')
        CTIToken(self.account).get(self.address).vote(index, amount)
        self.uncache()  # amount of token is burned in vote().
