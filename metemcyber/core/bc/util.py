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

import json
from getpass import getpass
from typing import Tuple, cast

from eth_account.messages import encode_defunct
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from web3.auto import w3

ADDRESS0 = cast(ChecksumAddress, '0x{:040x}'.format(0))


def sign_message(message: str, private_key: str) -> str:
    enc_msg = encode_defunct(text=message)
    signed_msg = w3.eth.account.sign_message(enc_msg, private_key=private_key)
    signature = signed_msg.signature.hex()
    return signature


def verify_message(message: str, signature: str) -> ChecksumAddress:
    enc_msg = encode_defunct(text=message)
    signer = w3.eth.account.recover_message(enc_msg, signature=HexBytes(signature))
    return signer


def decode_keyfile(filename: str) -> Tuple[ChecksumAddress, str]:
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    with open(filename) as keyfile:
        enc_data = keyfile.read()
    address = Web3.toChecksumAddress(json.loads(enc_data)['address'])
    word = getpass('Enter password for keyfile:')
    private_key = w3.eth.account.decrypt(enc_data, word).hex()
    return Web3.toChecksumAddress(address), private_key
