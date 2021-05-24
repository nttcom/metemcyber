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
from typing import List, Tuple

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import decode_keyfile
from metemcyber.core.logger import get_logger
from metemcyber.core.multi_solver import MCSServer, SolverManager, mcs_console

LOGGER = get_logger(name='solver_client', file_prefix='core')


def main(args):
    if args.mode == 'server':
        mgr = SolverManager(args.endpoint_url)
        server = MCSServer(mgr, args.work_dir)
        server.run()
    else:
        if args.keyfile:
            eoaa, pkey = decode_keyfile(args.keyfile)
        else:
            eoaa, pkey = args.name, args.pkey
        mcs_console(Account(Ether(args.endpoint_url), eoaa, pkey), args.work_dir)


OPTIONS: List[Tuple[str, str, dict]] = [
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
    ('-e', '--endpoint', dict(
        action='store', dest='endpoint_url', required=True,
        help='Ethereum Provider Endpoint URL')),
    ('-w', '--workdir', dict(
        action='store', dest='work_dir', required=True,
        help='working dir where socket file is placed')),
]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, etc_opts in OPTIONS:
        PARSER.add_argument(sname, lname, **etc_opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
