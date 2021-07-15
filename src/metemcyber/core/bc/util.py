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
import os
from getpass import getpass
from typing import Callable, Tuple, cast

from eth_account.messages import encode_defunct
from eth_typing import ChecksumAddress, HexStr
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


def decode_keyfile(filename: str,
                   password_func: Callable[[], str] = lambda: getpass('Enter password for keyfile:')
                   ) -> Tuple[ChecksumAddress, str]:
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    with open(filename) as keyfile:
        enc_data = keyfile.read()
    address = Web3.toChecksumAddress(json.loads(enc_data)['address'])
    word = password_func()
    private_key = w3.eth.account.decrypt(enc_data, word).hex()
    return Web3.toChecksumAddress(address), private_key


def deploy_erc1820(eoa: ChecksumAddress, web3: Web3) -> None:
    src_dir = os.path.dirname(os.path.abspath(__file__))
    erc1820_raw_tx_filepath = f'{src_dir}/erc1820.tx.raw'
    deployer_address = '0xa990077c3205cbDf861e17Fa532eeB069cE9fF96'
    contract_address = '0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24'
    code = web3.eth.getCode(contract_address)
    if code:  # already deployed
        return
    try:
        # send enough Ether to deploy erc1820.
        tx_hash = web3.eth.sendTransaction({
            'from': eoa,
            'to': deployer_address,
            'value': Web3.toWei('0.1', 'ether'),
        })
        tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
        assert tx_receipt['status'] == 1
    except Exception as err:
        raise ValueError('Sending Ether for ERC1820 failed') from err
    try:
        with open(erc1820_raw_tx_filepath, 'r') as fin:
            raw_tx = fin.read().strip()
        tx_hash = web3.eth.sendRawTransaction(cast(HexStr, raw_tx))
        tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
        assert tx_receipt['status'] == 1
    except Exception as err:
        raise ValueError('Sending ERC1820 raw transaction failed') from err
