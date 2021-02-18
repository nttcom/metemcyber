#
#    Copyright 2021, NTT Communications Corp.
#
#    Licensed under the Apache License, Version 2.0 (the 'License');
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an 'AS IS' BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

'''
usage:  metemctl account
        metemctl account info [options]
        metemctl account okawari [options]
        metemctl account send-ether <dest> <value> [options]

options:
    -h, --help
    -a, --eoa <address>

'''
from docopt import docopt
import configparser
from subprocess import call
import requests
import json
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import geth_poa_middleware
from web3.middleware import construct_sign_and_send_raw_middleware
from getpass import getpass
import sys
import os
import re

CONFIG_INI_FILEPATH = 'metemctl.ini'

def decode_keyfile(filename, w3):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    try:
        with open(filename) as keyfile:
            enc_data = keyfile.read()
        address = Web3.toChecksumAddress(json.loads(enc_data)['address'])
        word = os.getenv('METEMCTL_KEYFILE_PASSWORD', "")
        if word == "":
            print('You can also use an env METEMCTL_KEYFILE_PASSWORD.')
            word = getpass('Enter password for keyfile:')
            
        private_key = w3.eth.account.decrypt(enc_data, word).hex()
        return address, private_key
    except Exception as err:
        print('ERROR:', err)
        print('cannot decode keyfile:', os.path.basename(filename))
        sys.exit()


if __name__ == '__main__':

    args = docopt(__doc__)

    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)

    endpoint = config['general']['endpoint_url']
    w3 = Web3(Web3.HTTPProvider(endpoint))
    keyfile_path = config['general']['keyfile']
    my_account_id, my_private_key = decode_keyfile(keyfile_path, w3)
    w3.eth.defaultAccount = my_account_id

    # get wallet address
    if args['--eoa']:
        w3.eth.defaultAccount = args['--eoa']
    w3.eth.defaultAccount = Web3.toChecksumAddress(w3.eth.defaultAccount)
    # send money request
    if args['okawari']:
        # get access token for slack 
        slack_url = config['general']['slack_webhook_url']

        # send wallet address to slack(#okawari)
        requests.post(
            slack_url,
            data = json.dumps({
                'text': w3.eth.defaultAccount
            })
        )

    # show user account infomation
    elif args['info']:
        # set the access point of Web3
        if w3.isConnected():
            # PoA であれば geth_poa_middleware を利用
            try:
                w3.eth.getBlock('latest')
            except ExtraDataLengthError:
                w3.middleware_onion.inject(geth_poa_middleware, layer=0)

            # check wallet in the eoa address
            balance = w3.eth.getBalance(w3.eth.defaultAccount)
            
            # print balance of wallet
            print('--------------------')
            print('Summary')
            print('  - EOA Address:', w3.eth.defaultAccount)
            print('  - Balance:', balance, 'Wei')
            print('--------------------')
    elif args['send-ether'] and args['<value>']:
        # load account


        # load send address
        # PoA であれば geth_poa_middleware を利用
        try:
            w3.eth.getBlock("latest")
        except ExtraDataLengthError:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if my_private_key:
            w3.middleware_onion.add(
                construct_sign_and_send_raw_middleware(my_private_key))

        eoa = args['<dest>']
        if not eoa.startswith('0x'): # add prefix "0x" for Web3.py
            eoa = '0x' + eoa
        if Web3.isAddress(eoa):
            if not Web3.isChecksumAddress(eoa):
                eoa = Web3.toChecksumAddress(eoa)
            # set balance
            value = Web3.toWei(args['<value>'], 'ether')
            # send transaction(tx)
            tx_hash = w3.eth.sendTransaction({'to': eoa, 'from': w3.eth.defaultAccount, 'value': value})
            # check send tx status
            tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
            if tx_receipt['status'] != 1:
                print('Payment failed.')
        else:
            print('Wrong address')        
    else:
        exit("Invalid command. See 'metemctl account --help'.")