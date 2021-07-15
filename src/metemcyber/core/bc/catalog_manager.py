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

from typing import Dict, List, Optional, Set

from eth_typing import ChecksumAddress

from .account import Account
from .catalog import Catalog


class CatalogManager():
    def __init__(self, account: Account) -> None:
        self.account: Account = account
        #                   catalog_address  catalog_id
        self.catalogs: Dict[ChecksumAddress, int] = {}
        self.actives: Set[ChecksumAddress] = set()

    def add(self, addresses: List[ChecksumAddress], activate=False) -> None:
        for address in addresses:
            catalog = Catalog(self.account).get(address)
            self.catalogs[address] = catalog.catalog_id
            if activate:
                self.actives.add(address)

    def remove(self, addresses: List[ChecksumAddress]) -> None:
        for address in addresses:
            if address not in self.catalogs.keys():
                raise Exception(f'No such catalog: {address}')
            del self.catalogs[address]
            self.actives.discard(address)

    def activate(self, addresses: List[ChecksumAddress]) -> None:
        for address in addresses:
            if address not in self.catalogs.keys():
                raise Exception(f'No such catalog: {address}')
            self.actives.add(address)

    def deactivate(self, addresses: List[ChecksumAddress]) -> None:
        for address in addresses:
            if address not in self.catalogs.keys():
                raise Exception(f'No such catalog: {address}')
            self.actives.discard(address)

    def _catalogs(self, active: Optional[bool]) -> Dict[ChecksumAddress, int]:
        return {addr: cid for addr, cid in self.catalogs.items()
                if active in (None, addr in self.actives)}

    @property
    def active_catalogs(self) -> Dict[ChecksumAddress, int]:
        return self._catalogs(active=True)

    @property
    def reserved_catalogs(self) -> Dict[ChecksumAddress, int]:
        return self._catalogs(active=False)

    @property
    def all_catalogs(self) -> Dict[ChecksumAddress, int]:
        return self._catalogs(active=None)

    def id2address(self, catalog_id: int) -> ChecksumAddress:
        tmp = [caddr for caddr, cid in self.catalogs.items()
               if cid == catalog_id]
        if not tmp:
            raise Exception('No such catalog id: ' + str(catalog_id))
        assert len(tmp) == 1
        return tmp[0]

    def address2id(self, address: ChecksumAddress) -> int:
        return self.catalogs[address]
