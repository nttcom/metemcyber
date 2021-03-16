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

from typing import List, Optional, Tuple

from eth_typing import ChecksumAddress
from web3 import Web3

from .cti_operator import CTIOperator

TASK_STATES = ['Pending', 'Accepted', 'Finished', 'Cancelled']


class Operator():
    def __init__(self, web3: Web3) -> None:
        self.web3: Web3 = web3
        self.address: Optional[ChecksumAddress] = None

    def get(self, address: ChecksumAddress) -> 'Operator':
        self.address = address
        return self

    def new(self) -> 'Operator':
        assert self.web3
        cti_operator = CTIOperator(self.web3).new()
        return self.get(cti_operator.address)

    def history(self, token: ChecksumAddress, limit: int, offset: int
                ) -> List[Tuple[int, ChecksumAddress, ChecksumAddress, ChecksumAddress, int]]:
        assert self.web3
        assert self.address
        return CTIOperator(self.web3).get(self.address).history(token, limit, offset)

    def cancel_challenge(self, task_id: int) -> None:
        assert self.web3
        assert self.address
        CTIOperator(self.web3).get(self.address).cancel_challenge(task_id)
