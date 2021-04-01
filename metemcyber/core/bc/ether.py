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

from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import construct_sign_and_send_raw_middleware, geth_poa_middleware
from web3.providers.rpc import HTTPProvider


class Ether:
    def __init__(self, endpoint):
        self.web3 = Web3(HTTPProvider(endpoint))
        if self.web3.isConnected():
            try:
                self.web3.eth.getBlock('latest')
            except ExtraDataLengthError:
                self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    def signature(self, private_key):

        # 署名付きトランザクションの準備とcoinbaseアカウントの作成
        cssrm = construct_sign_and_send_raw_middleware(private_key)
        acc = self.web3.eth.account.from_key(private_key)

        # プライベート鍵の変数は今後使わないので明示的に削除
        del private_key

        # ミドルウェアに署名付きトランザクションを設定
        # See
        # https://github.com/ethereum/web3.py/blob/master/web3/datastructures.py
        # pylint: disable=protected-access
        if 'sign_and_send_raw' in self.web3.middleware_onion._queue:
            self.web3.middleware_onion.replace('sign_and_send_raw', cssrm)
        else:
            self.web3.middleware_onion.add(cssrm, 'sign_and_send_raw')

        # coinbaseとしてアカウントを設定
        self.web3.eth.defaultAccount = acc.address

    def web3_with_signature(self, private_key):
        self.signature(private_key)
        return self.web3
