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
import json
import os
from argparse import Namespace
from signal import SIGINT
from subprocess import Popen
from threading import Thread
from time import sleep
from typing import List, Optional, Tuple
from urllib.request import Request, urlopen

from eth_typing import ChecksumAddress
from psutil import NoSuchProcess, Process
from werkzeug.datastructures import EnvironHeaders

from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_operator import CTIOperator
from metemcyber.core.bc.cti_token import CTIToken
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.solver import SIGNATURE_HEADER
from metemcyber.core.webhook import WebhookReceiver

LOGGER = get_logger(name='seeker', file_prefix='core')
TTY_FILEPATH = f'{APP_DIR}/.tty4seeker.lnk'
LIMIT_ATONCE = 16

CONFIG_SECTION = 'seeker'
DEFAULT_CONFIGS = {
    CONFIG_SECTION: {
        'listen_address': '127.0.0.1',
        'listen_port': '0',
        'ngrok': '0',
    }
}


def tty_message(msg: str) -> None:
    try:
        with open(TTY_FILEPATH, 'w') as tty:
            if not tty.isatty:
                return
            tty.write(msg + '\n')
    except Exception:
        pass


def seeker_pid_filepath(app_dir: str) -> str:
    return f'{app_dir}/seeker.pid'


def asset_download_path(workspace: str, token_address: ChecksumAddress) -> str:
    return f'{workspace}/download/{token_address}.json'


def download_json(download_url: str, token_address: ChecksumAddress, workspace: str):
    try:
        request = Request(download_url, method='GET')
        with urlopen(request) as response:
            rdata = response.read()
            if isinstance(rdata, bytes):
                rdata = rdata.decode()
    except Exception as err:
        LOGGER.exception(err)
        msg = f'Failed download from {download_url}.'
        LOGGER.error(msg)
        tty_message(msg)
        return

    try:
        jdata = json.loads(rdata)
        title = jdata['Event']['info']
    except Exception:
        title = '(cannot decode title)'
    msg = f'Downloaded data. title: "{title}".'
    LOGGER.info(msg)
    tty_message(msg)

    try:
        if not os.path.isdir(workspace):
            os.makedirs(workspace)
        filepath = asset_download_path(workspace, token_address)
        with open(filepath, 'w') as fout:
            json.dump(jdata, fout, ensure_ascii=False, indent=2)
        msg = f'Saved downloaded data in {filepath}.'
        LOGGER.info(msg)
        tty_message(msg)
    except Exception as err:
        LOGGER.exception(err)
        msg = f'Saving downloaded data failed: {err}'
        LOGGER.error(msg)
        tty_message(msg)

    tty_message('(type CTRL-C to quit monitoring)')


class Resolver:
    webhook_server: WebhookReceiver
    endpoint_url: str
    operator_address: ChecksumAddress
    workspace: str

    @property
    def thread(self) -> Optional[Thread]:
        return self.webhook_server.thread

    def __init__(self, listen_address: str, listen_port: int,
                 workspace: str, endpoint_url: str, operator_address: ChecksumAddress):
        self.endpoint_url = endpoint_url
        self.operator_address = operator_address
        self.workspace = workspace
        self.webhook_server = WebhookReceiver(listen_address, listen_port,
                                              callback=self.resolve_request)

    def start(self) -> Tuple[str, int]:  # [listen_address, listen_port]
        return self.webhook_server.start()

    def resolve_request(self, headers: EnvironHeaders, body: str):
        sign = headers.get(SIGNATURE_HEADER)
        if sign is None:
            msg = f'Received request without signature.'
            LOGGER.error(msg)
            tty_message(msg)
            return
        LOGGER.debug(f'Received request. headers={headers}, body={body}.')
        tty_message('Incoming data...')
        try:
            jdata = self._precheck_request(body, sign)
        except KeyError as err:
            msg = f'Missing parameter: {err}'
            LOGGER.error(msg)
            tty_message(msg)
            return
        except Exception as err:
            LOGGER.exception(err)
            msg = f'Failed verifying data from solver: {err}'
            LOGGER.error(msg)
            tty_message(msg)
            return

        msg = f'Trying download_url for task {jdata["task_id"]} - ' + \
              f'token({jdata["token_address"]}): {jdata["download_url"]}'
        LOGGER.info(msg)
        tty_message(msg)
        download_json(jdata['download_url'], jdata['token_address'], self.workspace)

    def _precheck_request(self, body: str, sign: str) -> dict:
        account = Account(Ether(self.endpoint_url))
        jdata = json.loads(body)
        if jdata['solver'] != verify_message(body, sign):
            raise Exception('Signer mismatch.')
        tty_message(f'Data sender: {jdata["solver"]}.')
        operator = CTIOperator(account).get(self.operator_address)
        task = None
        offset = 0
        while True:
            tasks = operator.history(jdata['token_address'], None, LIMIT_ATONCE, offset)
            tmp = [item for item in tasks if item[0] == int(jdata['task_id'])]
            if tmp:
                task = tmp[0]
                break
            if len(tasks) < LIMIT_ATONCE:
                break
            offset += LIMIT_ATONCE

        if task is None:
            raise Exception(f'No such task id: {jdata["task_id"]}')
        _, t_addr, t_solver, _, _ = task
        if t_addr != jdata['token_address'] or t_solver != jdata['solver']:
            raise Exception('Task info mismatch')
        token = CTIToken(account).get(t_addr)
        if not token.is_operator(t_solver, token.publisher):
            raise Exception(f'RevokedOperator: {t_solver}')
        return jdata


class Seeker():
    cmd_args_base: List[str] = ['python3', __file__]
    app_dir: str
    endpoint_url: str
    workspace: str
    operator_address: ChecksumAddress
    pid: int = 0
    listen_address: str
    listen_port: int

    @property
    def cmd_args(self) -> List[str]:
        return Seeker.cmd_args_base + [  # see ARGUMENTS of this file
            self.app_dir,
            self.endpoint_url,
            self.workspace,
            self.operator_address,
            self.listen_address,
            str(self.listen_port),
        ]

    def __init__(self, app_dir: str, endpoint_url: str, workspace: str,
                 operator_address: ChecksumAddress):
        self.app_dir = app_dir
        self.endpoint_url = endpoint_url
        self.workspace = workspace
        self.listen_address = ''  # set on start()
        self.listen_port = 0  # set on start()
        self.operator_address = operator_address

        self.pid, self.listen_address, self.listen_port = self.check_running()
        if operator_address and endpoint_url:
            operator = CTIOperator(Account(Ether(endpoint_url))).get(operator_address)
            if operator.version < 1:
                raise Exception(
                    f'Operator({operator_address}) is version {operator.version} and '
                    'not support anonymous access.')

    #                               (pid|0, listen_address, listen_port)
    def check_running(self) -> Tuple[int, str, int]:
        try:
            with open(seeker_pid_filepath(self.app_dir), 'r') as fin:
                str_data = fin.readline().strip()
            str_pid, address, str_port = str_data.split('\t', 2)
            pid = int(str_pid)
        except Exception:
            return 0, '', 0
        try:
            proc = Process(pid)
            running_seeker = proc.cmdline()[:len(Seeker.cmd_args_base)]
            if len(running_seeker) > 1 and len(Seeker.cmd_args_base) > 1:
                # Python path locations are not always the same, so compare with arguments.
                if running_seeker[1] == Seeker.cmd_args_base[1]:
                    return pid, address, int(str_port)
            # found pid, but it's not a seeker. remove defunct data.
            LOGGER.info(f'got pid({pid}) which is not a seeker. remove defunct.')
            os.unlink(seeker_pid_filepath(self.app_dir))
            return 0, '', 0
        except NoSuchProcess:
            return 0, '', 0

    def start(self, listen_address: str, listen_port: int) -> None:
        """launch Resolver by calling main() as another process
        """
        if self.pid:
            raise Exception(f'Already running on pid({self.pid}).')
        self.listen_address = listen_address
        self.listen_port = listen_port
        # Seeker needs to keep running in the background.
        # pylint pylint: disable=R1732
        proc = Popen(self.cmd_args, shell=False, start_new_session=True)
        for _cnt in range(5):
            sleep(1)
            self.pid, self.listen_address, self.listen_port = self.check_running()
            if self.pid:
                LOGGER.info(f'started. pid={self.pid}, '
                            f'address={self.listen_address}, port={self.listen_port}.')
                return
        LOGGER.error('Cannot start webhook.')
        proc.kill()
        raise Exception('Cannot start webhook')

    def stop(self) -> None:
        pid, _address, _port = self.check_running()
        if not pid:
            raise Exception('Not running')
        try:
            LOGGER.info(f'stopping process({pid}).')
            os.kill(pid, SIGINT)
        except Exception as err:
            raise Exception(f'Cannot stop webhook(pid={pid})') from err


def main(args: Namespace):
    pid_file = seeker_pid_filepath(args.app_dir)
    try:
        resolver = Resolver(
            args.listen_address, args.listen_port,
            args.workspace, args.endpoint_url, args.operator_address)
        address, port = resolver.start()
        pid = os.getpid()
        with open(pid_file, 'w') as fout:
            fout.write(f'{pid}\t{address}\t{port}\n')
        assert resolver.thread
        resolver.thread.join()
    except KeyboardInterrupt:
        LOGGER.info('caught SIGINT.')
    finally:
        if os.path.exists(pid_file):
            os.unlink(pid_file)


OPTIONS: List[Tuple[str, str, dict]] = [
]
ARGUMENTS: List[Tuple[str, dict]] = [
    ('app_dir', dict(action='store', type=str, help='application directory')),
    ('endpoint_url', dict(action='store', type=str, help='Block chain RPC provider URL')),
    ('workspace', dict(action='store', type=str, help='metemctl workspace directory')),
    ('operator_address', dict(action='store', type=ChecksumAddress, help='CTIOperator address')),
    ('listen_address', dict(action='store', type=str, help='seeker listen address')),
    ('listen_port', dict(action='store', type=int, help='seeker listen port (0 for auto-detect)')),
]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, opts in OPTIONS:
        PARSER.add_argument(sname, lname, **opts)
    for name, opts in ARGUMENTS:
        PARSER.add_argument(name, **opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
