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

from .account import Account
from .cti_operator import CTIOperator

TASK_STATES = ['Pending', 'Accepted', 'Finished', 'Cancelled']


class Operator():
    def __init__(self, account: Account) -> None:
        self.account: Account = account
        self.address: Optional[ChecksumAddress] = None

    def get(self, address: ChecksumAddress) -> 'Operator':
        self.address = address
        return self

    def new(self) -> 'Operator':
        cti_operator = CTIOperator(self.account).new()
        return self.get(cti_operator.address)

    def history(self, token: ChecksumAddress, limit: int, offset: int
                ) -> List[Tuple[int, ChecksumAddress, ChecksumAddress, ChecksumAddress, int]]:
        assert self.address
        return CTIOperator(self.account).get(self.address).history(token, limit, offset)

    def cancel_challenge(self, task_id: int) -> None:
        assert self.address
        CTIOperator(self.account).get(self.address).cancel_challenge(task_id)
