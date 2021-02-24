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

import argparse
import logging
from web3.providers.rpc import HTTPProvider
from client import decode_keyfile
from multi_solver import MCSolver, MCSServer, mcs_client

logging.basicConfig(format='[%(levelname)s]: %(message)s')
LOGGER = logging.getLogger('common')
LOGGER.setLevel(logging.DEBUG)

def main(args):
    if args.keyfile:
        eoaa, pkey = decode_keyfile(args.keyfile)
    else:
        eoaa, pkey = args.name, args.pkey
#    assert eoaa and pkey
    if args.operator:
        operator_address, pluginfile = args.operator.split('@', 1)
    else:
        operator_address = pluginfile = None

    if args.mode == 'server':
        provider = HTTPProvider(args.endpoint_uri)
        mcs = MCSolver(provider, eoaa, pkey, operator_address, pluginfile)
        server = MCSServer(mcs)
        server.run()
    else:
        mcs_client(eoaa, pkey)

OPTIONS = [
    ('-m', '--mode', dict(
        action='store', required=True,
        choices=['server', 'client'])),
    ('-f', '--keyfile', dict(
        action='store', dest='keyfile',
        help='キーファイル')),
    ('-u', '--user', dict(
        action='store', dest='name',
        help='ログインユーザ(EOA Address)')),
    ('-k', '--privatekey', dict(
        action='store', dest='pkey',
        help='プライベートキー')),
    ('-p', '--provider', dict(
        action='store', dest='endpoint_uri',
        help='Ethereum Provider Endpoint URI')),
    ('-o', '--operator', dict(
        action='store', dest='operator',
        help='CTIOperatorContractAddress[@SolverPluginFilename]')),
    ]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, etc_opts in OPTIONS:
        PARSER.add_argument(sname, lname, **etc_opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
