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
from threading import Thread
from time import sleep
from typing import Optional, Tuple
from urllib.request import Request, urlopen

from eth_typing import ChecksumAddress
from omegaconf.dictconfig import DictConfig
from psutil import Process
from werkzeug.datastructures import EnvironHeaders

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_operator import CTIOperator
from metemcyber.core.bc.cti_token import CTIToken
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.solver import SIGNATURE_HEADER
from metemcyber.core.webhook import WebhookReceiver

LOGGER = get_logger(name='seeker', file_prefix='core')
LIMIT_ATONCE = 16


def tty_message(config: DictConfig, msg: str) -> None:
    try:
        with open(config.runtime.seeker_tty_filepath, 'w', encoding='utf-8') as tty:
            if not tty.isatty:
                return
            tty.write(msg + '\n')
    except Exception:
        pass


def download_json(download_url: str, token_address: ChecksumAddress, config: DictConfig):
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
        tty_message(config, msg)
        return

    try:
        jdata = json.loads(rdata)
        title = jdata['Event']['info']
    except Exception:
        title = '(cannot decode title)'
    msg = f'Downloaded data. title: "{title}".'
    LOGGER.info(msg)
    tty_message(config, msg)

    try:
        filepath = f'{config.runtime.seeker_download_filepath}/{token_address}.json'
        with open(filepath, 'w', encoding='utf-8') as fout:
            json.dump(jdata, fout, ensure_ascii=False, indent=2)
        msg = f'Saved downloaded data in {filepath}.'
        LOGGER.info(msg)
        tty_message(config, msg)
    except Exception as err:
        LOGGER.exception(err)
        msg = f'Saving downloaded data failed: {err}'
        LOGGER.error(msg)
        tty_message(config, msg)

    tty_message(config, '(type CTRL-C to quit monitoring)')


class Resolver:
    webhook_server: WebhookReceiver
    config: DictConfig

    @property
    def thread(self) -> Optional[Thread]:
        return self.webhook_server.thread

    def __init__(self, config: DictConfig):
        self.config = config
        self.webhook_server = WebhookReceiver(self.config.blockchain.seeker.listen_address,
                                              self.config.blockchain.seeker.listen_port,
                                              callback=self.resolve_request)

    def start(self) -> Tuple[str, int]:  # [listen_address, listen_port]
        return self.webhook_server.start()

    def resolve_request(self, headers: EnvironHeaders, body: str):
        sign = headers.get(SIGNATURE_HEADER)
        if sign is None:
            msg = f'Received request without signature.'
            LOGGER.error(msg)
            tty_message(self.config, msg)
            return
        LOGGER.debug(f'Received request. headers={headers}, body={body}.')
        tty_message(self.config, 'Incoming data...')
        try:
            jdata = self._precheck_request(body, sign)
        except KeyError as err:
            msg = f'Missing parameter: {err}'
            LOGGER.error(msg)
            tty_message(self.config, msg)
            return
        except Exception as err:
            LOGGER.exception(err)
            msg = f'Failed verifying data from solver: {err}'
            LOGGER.error(msg)
            tty_message(self.config, msg)
            return

        msg = f'Trying download_url for task {jdata["task_id"]} - ' + \
              f'token({jdata["token_address"]}): {jdata["download_url"]}'
        LOGGER.info(msg)
        tty_message(self.config, msg)
        download_json(jdata['download_url'], jdata['token_address'], self.config)

    def _precheck_request(self, body: str, sign: str) -> dict:
        account = Account(Ether(self.config.blockchain.endpoint_url))
        jdata = json.loads(body)
        if jdata['solver'] != verify_message(body, sign):
            raise Exception('Signer mismatch.')
        tty_message(self.config, f'Data sender: {jdata["solver"]}.')
        operator = CTIOperator(account).get(self.config.blockchain.operator.address)
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
    config: DictConfig
    pid: int = 0
    listen_address: str
    listen_port: int

    def __init__(self, config: DictConfig):
        self.config = config
        self.pid, self.listen_address, self.listen_port = self._check_running()

        operator = CTIOperator(Account(Ether(self.config.blockchain.endpoint_url)))
        operator.get(self.config.blockchain.operator.address)
        if operator.version < 1:
            raise Exception(
                f'Operator({operator.address}) is version {operator.version} and '
                'not support anonymous access.')

    #                               (pid|0, listen_address, listen_port)
    def _check_running(self) -> Tuple[int, str, int]:
        try:
            with open(self.config.runtime.seeker_pid_filepath, 'r', encoding='utf-8') as fin:
                str_data = fin.readline().strip()
                str_args = fin.readline().strip()
            str_pid, address, str_port = str_data.split('\t', 2)
            expected_cmd_args = str_args.split('\t')
            pid = int(str_pid)
        except Exception:
            return 0, '', 0
        try:
            cmdline = Process(pid).cmdline()
            if cmdline != expected_cmd_args:
                raise Exception(f'command args mismatch')
            return pid, address, int(str_port)
        except Exception:
            pass
        if os.path.exists(self.config.runtime.solver_pid_filepath):
            os.unlink(self.config.runtime.seeker_pid_filepath)  # remove defunct
        return 0, '', 0

    def start(self):
        if self.pid > 0:
            raise Exception(f'Already running on pid({self.pid}).')
        pid = os.fork()
        if pid > 0:  # parent
            for _cnt in range(3):
                sleep(1)
                running = self._check_running()
                if running[0] == pid:
                    self.pid, self.listen_address, self.listen_port = running
                    return
            raise Exception('Cannot start Seeker')

        # child
        try:
            os.setsid()
            resolver = Resolver(self.config)
            address, port = resolver.start()
            pid = os.getpid()
            str_cmdline = '\t'.join(Process(pid).cmdline())
            with open(self.config.runtime.seeker_pid_filepath, 'w', encoding='utf-8') as fout:
                fout.write(f'{pid}\t{address}\t{port}\n')
                fout.write(f'{str_cmdline}\n')
            assert resolver.thread
            resolver.thread.join()
        except KeyboardInterrupt:
            LOGGER.info('caught SIGINT.')
        finally:
            if os.path.exists(self.config.runtime.seeker_pid_filepath):
                os.unlink(self.config.runtime.seeker_pid_filepath)
        sys.exit(0)

    def stop(self) -> None:
        pid, _address, _port = self._check_running()
        if not pid:
            raise Exception('Not running')
        try:
            LOGGER.info(f'stopping process({pid}).')
            os.kill(pid, SIGINT)
        except Exception as err:
            raise Exception(f'Cannot stop webhook(pid={pid})') from err
