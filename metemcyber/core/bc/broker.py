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

from .account import Account
from .catalog import Catalog
from .cti_broker import CTIBroker
from .cti_token import CTIToken
from .token import Token

PTS_RATE: int = 10**18  # FIXME: should import from somewhere


class Broker():
    #            {broker:              {catalog:             {token:           amount}}}
    amounts: Dict[ChecksumAddress, Dict[ChecksumAddress, Dict[ChecksumAddress, int]]] = {}

    def __init__(self, account: Account) -> None:
        self.account: Account = account
        self.address: Optional[ChecksumAddress] = None

    def get(self, address: ChecksumAddress) -> Broker:
        self.address = address
        return self

    def new(self) -> Broker:
        cti_broker = CTIBroker(self.account).new()
        return self.get(cti_broker.address)

    def uncache(self, catalog: Optional[ChecksumAddress] = None,
                token: Optional[ChecksumAddress] = None,
                entire: bool = False) -> None:
        if entire:
            del Broker.amounts
            Broker.amounts = {}
            return
        assert self.address
        if self.address not in Broker.amounts.keys():
            return
        if catalog is None:
            Broker.amounts.pop(self.address, None)
            return
        if catalog not in Broker.amounts[self.address].keys():
            return
        if token is None:
            Broker.amounts[self.address].pop(catalog, None)
            return
        Broker.amounts[self.address][catalog].pop(token, None)

    def _fill_amounts(self, catalog: ChecksumAddress) -> None:
        assert self.address
        if self.address not in Broker.amounts.keys():
            Broker.amounts[self.address] = {}
        bmap: dict = Broker.amounts[self.address]
        if catalog not in bmap.keys():
            bmap[catalog] = {}
        cmap: dict = bmap[catalog]
        queries = list(Catalog(self.account).get(catalog).tokens.keys() - cmap.keys())
        if len(queries) == 0:  # already filled
            return
        cti_broker = CTIBroker(self.account).get(self.address)
        amounts = cti_broker.get_amounts(catalog, queries)
        for idx, token in enumerate(queries):
            cmap[token] = amounts[idx]

    def get_amount(self, catalog: ChecksumAddress, token: ChecksumAddress) -> int:
        assert self.address
        self._fill_amounts(catalog)
        try:
            return Broker.amounts[self.address][catalog][token]
        except KeyError as err:
            raise Exception('No such token or catalog or broker') from err

    def get_amounts(self, catalog: ChecksumAddress, tokens: List[ChecksumAddress]) -> List[int]:
        assert self.address
        self._fill_amounts(catalog)
        try:
            return [Broker.amounts[self.address][catalog][token] for token in tokens]
        except KeyError as err:
            raise Exception('No such token or catalog or broker') from err

    def consign(self, catalog: ChecksumAddress, token: ChecksumAddress,
                amount: int) -> None:
        assert self.address
        cti_token = CTIToken(self.account).get(token)
        cti_broker = CTIBroker(self.account).get(self.address)
        cti_token.authorize_operator(self.address)
        try:
            cti_broker.consign_token(catalog, token, amount)
            self.uncache(catalog, token)
            Token(self.account).get(token).uncache()  # FIXME: should I?
        finally:
            cti_token.revoke_operator(self.address)

    def takeback(self, catalog: ChecksumAddress, token: ChecksumAddress,
                 amount: int) -> None:
        assert self.address
        cti_broker = CTIBroker(self.account).get(self.address)
        cti_broker.takeback_token(catalog, token, amount)
        self.uncache(catalog, token)
        Token(self.account).get(token).uncache()  # FIXME: should I?

    def buy(self, catalog: ChecksumAddress, token: ChecksumAddress,
            price: int, allow_cheaper: bool = False) -> None:
        assert self.address
        wei = price * PTS_RATE
        cti_broker = CTIBroker(self.account).get(self.address)
        cti_broker.buy_token(catalog, token, wei, allow_cheaper)
        self.uncache(catalog, token)
        Token(self.account).get(token).uncache()  # FIXME: should I?
