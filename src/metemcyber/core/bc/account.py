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

from typing import Callable, Optional, cast

from eth_typing import ChecksumAddress
from web3 import Web3

from .ether import Ether
from .util import ADDRESS0, sign_message
from .wallet import Wallet


class Account:
    def __init__(self, ether: Ether, eoa: ChecksumAddress = ADDRESS0, pkey: Optional[str] = None
                 ) -> None:
        self.eoa: ChecksumAddress = Web3.toChecksumAddress(eoa)
        self.web3: Web3 = ether.web3_with_signature(pkey) if pkey else ether.web3
        if pkey:
            assert eoa != ADDRESS0
            self.wallet: Wallet = Wallet(self.web3, eoa)
            self.sign_message: Callable[[str], str] = lambda x: sign_message(x, cast(str, pkey))
