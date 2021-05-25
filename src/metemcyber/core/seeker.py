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
import sys
from signal import SIGINT
from subprocess import Popen
from time import sleep
from typing import List, Optional, Tuple, cast
from urllib.request import Request, urlopen

from eth_typing import ChecksumAddress
from psutil import NoSuchProcess, Process
from werkzeug.datastructures import EnvironHeaders

from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.operator import Operator
from metemcyber.core.bc.util import verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.solver import SIGNATURE_HEADER
from metemcyber.core.util import merge_config
from metemcyber.core.webhook import WebhookReceiver

LOGGER = get_logger(name='seeker', file_prefix='core')
TTY_FILEPATH = f'{APP_DIR}/.tty4seeker.lnk'
LIMIT_ATONCE = 16

CONFIG_SECTION = 'seeker'
DEFAULT_CONFIGS = {
    CONFIG_SECTION: {
        'downloaded_cti_path': f'{APP_DIR}/workspace/download',
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


def download_json(download_url: str, token_address: ChecksumAddress, dir_path: str) -> None:
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
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)
        filepath = f'{dir_path}/{token_address}.json'
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


class Resolver(WebhookReceiver):
    def __init__(self, listen_address: str, listen_port: int,
                 download_path: str, endpoint_url: str, operator_address: ChecksumAddress):
        super().__init__(listen_address, listen_port)
        self.download_path = download_path
        self.endpoint_url = endpoint_url
        self.operator_address = operator_address

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
            jdata = json.loads(body)
            if jdata['from'] != verify_message(body, sign):
                raise Exception('Signer mismatch.')
            tty_message(f'Data sender: {jdata["from"]}.')
            operator = Operator(Account(Ether(self.endpoint_url))).get(self.operator_address)
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
            if t_addr != jdata['token_address'] or t_solver != jdata['from']:
                raise Exception('Task info mismatch')
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
        download_json(jdata['download_url'], jdata['token_address'], self.download_path)


class Seeker():
    cmd_args_base = ['python3', __file__]

    @property
    def cmd_args(self) -> List[str]:
        args = Seeker.cmd_args_base + [
            self.config[CONFIG_SECTION]['listen_address'],
            self.config[CONFIG_SECTION]['listen_port'],
            self.app_dir,
            self.operator_address,
            self.endpoint_url,
        ]
        if self.config_path:
            args += [self.config_path]
        return args

    def __init__(self, app_dir: str, operator_address: ChecksumAddress, endpoint_url: str = '',
                 config_path: Optional[str] = None
                 ) -> None:
        self.app_dir = app_dir
        self.config_path = config_path
        self.config = merge_config(config_path, DEFAULT_CONFIGS)
        pid, address, port = self.check_running()
        self.pid: int = pid
        self.address: Optional[str] = address
        self.port: int = port
        self.operator_address = operator_address
        self.endpoint_url = endpoint_url
        if operator_address and endpoint_url:
            operator = Operator(Account(Ether(endpoint_url))).get(operator_address)
            if operator.version < 1:
                raise Exception(
                    f'Operator({operator_address}) is version {operator.version} and '
                    'not support anonymous access.')

    #                               (pid|0, listen_address, listen_port)
    def check_running(self) -> Tuple[int, Optional[str], int]:
        try:
            with open(seeker_pid_filepath(self.app_dir), 'r') as fin:
                str_data = fin.readline().strip()
            str_pid, address, str_port = str_data.split('\t', 2)
            pid = int(str_pid)
        except Exception:
            return 0, None, 0
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
            return 0, None, 0
        except NoSuchProcess:
            return 0, None, 0

    def start(self) -> None:
        """launch Resolver by calling main() as another process
        """
        if self.pid:
            raise Exception(f'Already running on pid({self.pid}).')
        # Seeker needs to keep running in the background.
        # pylint pylint: disable=R1732
        proc = Popen(self.cmd_args, shell=False)
        for _cnt in range(5):
            sleep(1)
            self.pid, self.address, self.port = self.check_running()
            if self.pid:
                LOGGER.info(f'started. pid={self.pid}, address={self.address}, port={self.port}.')
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


def main(argv: List[str]):
    listen_address, listen_port, app_dir, operator_address, endpoint_url = argv[:5]
    config_path = argv[5] if len(argv) > 5 else None
    pid_file = seeker_pid_filepath(app_dir)
    try:
        config = merge_config(config_path, DEFAULT_CONFIGS)
        resolver = Resolver(listen_address, int(listen_port),
                            config[CONFIG_SECTION]['downloaded_cti_path'],
                            endpoint_url,
                            cast(ChecksumAddress, operator_address))
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


if __name__ == '__main__':
    if len(sys.argv) < 5:
        raise Exception('Not enough arguments')
    main(sys.argv[1:])
