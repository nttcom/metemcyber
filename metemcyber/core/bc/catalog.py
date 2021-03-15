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

from typing import Dict, Optional
from uuid import UUID

from eth_typing import ChecksumAddress
from web3 import Web3

from .cti_catalog import CTICatalog


class TokenInfo():
    def __init__(self):
        self.address = None
        self.token_id = None
        self.owner = None
        self.uuid = None
        self.title = None
        self.price = None
        self.operator = None
        self.like_count = None


class CatalogInfo():
    def __init__(self):
        self.address = None
        self.catalog_id = None
        self.owner = None
        self.private = None
        self.tokens: Dict[ChecksumAddress, TokenInfo] = {}

    def tokeninfo_by_address(
            self, address: ChecksumAddress) -> Optional[TokenInfo]:
        return self.tokens.get(address)

    def tokeninfo_by_id(self, token_id: int) -> Optional[TokenInfo]:
        tmp = [info for info in self.tokens.values()
               if info.token_id == token_id]
        return tmp[0] if tmp else None


class Catalog():
    __addressed_catalogs: Dict[ChecksumAddress, CatalogInfo] = {}

    @property
    def _catalogs_by_address(self):
        return Catalog.__addressed_catalogs

    @property
    def _catalogs_by_id(self):
        return {info['catalog_id']: info
                for info in Catalog.__addressed_catalogs.values()}

    def __init__(self, web3: Web3) -> None:
        self.web3: Web3 = web3
        self.address: Optional[ChecksumAddress] = None
        self.catalog_id: int = 0
        self.owner: Optional[ChecksumAddress] = None
        self.private: Optional[bool] = None
        self.tokens: Dict[ChecksumAddress, TokenInfo] = {}

    def get(self, address: ChecksumAddress) -> 'Catalog':
        assert self.web3
        self.address = address
        self._sync_catalog()
        return self

    def get_by_id(self, catalog_id: int) -> 'Catalog':
        return self.get(self._catalogs_by_id()[catalog_id].address)

    def new(self, private: bool) -> 'Catalog':
        assert self.web3
        cti_catalog = CTICatalog(self.web3).new(private)
        return self.get(cti_catalog.address)

    def uncache(self, entire: bool = False) -> None:
        if entire:
            del Catalog.__addressed_catalogs
            Catalog.__addressed_catalogs = {}
        else:
            assert self.address
            if self.address in Catalog.__addressed_catalogs.keys():
                del Catalog.__addressed_catalogs[self.address]

    @staticmethod
    def _gen_catalog_id() -> int:
        return max([val.catalog_id for val
                    in Catalog.__addressed_catalogs.values()] + [0]
                   ) + 1

    def _sync_catalog(self) -> None:
        assert self.web3
        assert self.address
        cinfo = self._catalogs_by_address.get(self.address)
        if not cinfo:
            cinfo = CatalogInfo()
            cinfo.address = self.address
            cinfo.catalog_id = self._gen_catalog_id()
            Catalog.__addressed_catalogs[self.address] = cinfo
            cti_catalog = CTICatalog(self.web3).get(self.address)
            cinfo.owner = cti_catalog.get_owner()
            cinfo.private = cti_catalog.is_private()
            for taddr in cti_catalog.list_token_uris():
                tinfo = TokenInfo()
                tid, owner, uuid, title, price, operator, lcount = \
                    cti_catalog.get_cti_info(taddr)
                tinfo.address = taddr
                tinfo.token_id = tid
                tinfo.owner = owner
                tinfo.uuid = uuid
                tinfo.title = title
                tinfo.price = price
                tinfo.operator = operator
                tinfo.like_count = lcount
                cinfo.tokens[taddr] = tinfo
        self.catalog_id = cinfo.catalog_id
        self.owner = cinfo.owner
        self.private = cinfo.private
        self.tokens = cinfo.tokens

    def get_tokeninfo(self, address: ChecksumAddress) -> TokenInfo:
        if address not in self.tokens.keys():
            raise Exception(f'No such token({address}) on catalog({self.address})')
        return self.tokens[address]

    def get_tokeninfo_by_id(self, token_id: int) -> TokenInfo:
        return self.get_tokeninfo(self.id2address(token_id))

    def id2address(self, token_id: int) -> ChecksumAddress:
        cinfo = self._catalogs_by_address.get(self.address)
        tmp = [tinfo.address for tinfo in cinfo.tokens.values() if tinfo.token_id == token_id]
        if not tmp:
            raise Exception(f'No such token id({token_id}) on catalog({self.address})')
        assert len(tmp) == 1
        return tmp[0]

    def register_cti(self, token: ChecksumAddress, uuid: UUID, title: str, price: int) -> None:
        if price < 0:
            raise Exception(f'Invalid price: {price}')
        cti_catalog = CTICatalog(self.web3).get(self.address)
        cti_catalog.register_cti(token, uuid, title, price, '')

    def publish_cti(self, producer: ChecksumAddress, token: ChecksumAddress) -> None:
        assert self.address
        cti_catalog = CTICatalog(self.web3).get(self.address)
        cti_catalog.publish_cti(producer, token)

    def modify_cti(self, token: ChecksumAddress, uuid: UUID, title: str, price: int) -> None:
        if price < 0:
            raise Exception(f'Invalid price: {price}')
        assert self.address
        cti_catalog = CTICatalog(self.web3).get(self.address)
        cti_catalog.modify_cti(token, uuid, title, price, '')

    def unregister_cti(self, token: ChecksumAddress) -> None:
        assert self.address
        cti_catalog = CTICatalog(self.web3).get(self.address)
        cti_catalog.unregister_cti(token)
