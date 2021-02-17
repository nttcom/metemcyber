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

CONFIG_INI_FILEPATH = 'metemctl.ini'

if __name__ == '__main__':

    args = docopt(__doc__)

    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)
    # get wallet address
    wallet = config['general']['wallet_addr']
    if args['--eoa']:
        wallet = args['--eoa']
    wallet = Web3.toChecksumAddress(wallet)
    # send money request
    if args['okawari']:
        # get access token for slack 
        slack_url = config['general']['slack_webhook_url']

        # send wallet address to slack(#okawari)
        requests.post(
            slack_url,
            data = json.dumps({
                'text': wallet
            })
        )

    # show user account infomation
    elif args['info']:
        # set the access point of Web3
        endpoint = config['general']['endpoint_url']
        w3 = Web3(Web3.HTTPProvider(endpoint))
        if w3.isConnected():
            # PoA であれば geth_poa_middleware を利用
            try:
                w3.eth.getBlock('latest')
            except ExtraDataLengthError:
                w3.middleware_onion.inject(geth_poa_middleware, layer=0)

            # check wallet in the eoa address
            balance = w3.eth.getBalance(wallet)
            
            # print balance of wallet
            print('--------------------')
            print('Summary')
            print('  - EOA Address:', wallet)
            print('  - Balance:', balance, 'Wei')
            print('--------------------')
         
    else:
        exit("Invalid command. See 'metemctl account --help'.")