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

class Wallet:
    def __init__(self, web3, eoa):
        self.web3 = web3
        self.eoa = eoa
        self.__balance = self._get_balance()

    def _get_balance(self):
        return self.web3.eth.getBalance(self.eoa)

    @property
    def balance(self):
        self.__balance = self._get_balance()
        return self.__balance
