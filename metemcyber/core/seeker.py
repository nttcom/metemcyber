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
from typing import List, Optional, Tuple
from urllib.request import Request, urlopen

from eth_typing import ChecksumAddress
from psutil import NoSuchProcess, Process
from werkzeug.datastructures import EnvironHeaders

from metemcyber.core.bc.util import verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.solver import SIGNATURE_HEADER
from metemcyber.core.webhook import WebhookReceiver

LOGGER = get_logger(name='seeker', file_prefix='core')

DOWNLOADED_CTI_PATH = './download'  # FIXME: should import from somewhere
SEEKER_PID_FILEPATH = './seeker.pid'  # FIXME


def download_json(download_url: str, token_address: ChecksumAddress) -> None:
    try:
        request = Request(download_url, method='GET')
        with urlopen(request) as response:
            rdata = response.read()
    except Exception as err:
        LOGGER.exception(err)
        LOGGER.error(f'Failed download from {download_url}.')
        return

    try:
        jdata = json.loads(rdata)
        title = jdata['Event']['info']
    except Exception:
        title = '(cannot decode title)'
    LOGGER.info(f'Downloaded data, title: {title}.')

    try:
        if not os.path.isdir(DOWNLOADED_CTI_PATH):
            os.makedirs(DOWNLOADED_CTI_PATH)
        filepath = f'{DOWNLOADED_CTI_PATH}/{token_address}.json'
        with open(filepath, 'wb') as fout:
            fout.write(rdata)
        LOGGER.info(f'Saved downloaded data in {filepath}.')
    except Exception as err:
        LOGGER.exception(err)
        LOGGER.error('Saving downloaded data failed.')


class Resolver(WebhookReceiver):
    @staticmethod
    def resolve_request(headers: EnvironHeaders, body: str) -> None:
        sign = headers.get(SIGNATURE_HEADER)
        if sign is None:
            LOGGER.error(f'Received request without signature. headers={headers}, body={body}.')
            return
        try:
            LOGGER.debug(f'Received request. headers={headers}, body={body}.')
            signer = verify_message(body, sign)
            LOGGER.debug(f'Calculated signer is {signer}.')
        except Exception as err:
            LOGGER.exception(err)
            LOGGER.error('Verify message failed')
        try:
            jdata = json.loads(body)
            download_url = jdata['download_url']
            token_address = jdata['token_address']
            assert download_url
            assert token_address

            #
            # FIXME: check signer is the owner of this token.
            #

        except Exception as err:
            LOGGER.exception(err)
            LOGGER.error('Decoding request body failed.')
            return
        LOGGER.info(f'Received download_url for token({token_address}): {download_url}')
        download_json(download_url, token_address)


class Seeker():
    cmd_args_base = ['python3', 'metemcyber/core/seeker.py']

    @property
    def cmd_args(self) -> List[str]:
        if self.local:
            return Seeker.cmd_args_base + ['127.0.0.1', '0']
        return Seeker.cmd_args_base + ['0.0.0.0', '0']

    @staticmethod
    def check_running() -> Tuple[int, Optional[str], int]:  # (pid|0, listen_address, listen_port)
        try:
            with open(SEEKER_PID_FILEPATH, 'r') as fin:
                str_data = fin.readline().strip()
            str_pid, address, str_port = str_data.split('\t', 2)
            pid = int(str_pid)
        except Exception:
            return 0, None, 0
        try:
            proc = Process(pid)
            if proc.cmdline()[:len(Seeker.cmd_args_base)] == Seeker.cmd_args_base:
                return pid, address, int(str_port)
            # found pid, but it's not a seeker. remove defunct data.
            LOGGER.info(f'got pid({pid}) which is not a seeker. remove defunct.')
            os.unlink(SEEKER_PID_FILEPATH)
            return 0, None, 0
        except NoSuchProcess:
            return 0, None, 0

    def __init__(self, local: bool = True) -> None:
        self.local: bool = local
        pid, address, port = self.check_running()
        self.pid: int = pid
        self.address: Optional[str] = address
        self.port: int = port

    def start(self) -> None:
        """launch Resolver by calling main() as another process
        """
        if self.pid:
            raise Exception(f'Already running on pid({self.pid}).')
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


def main(listen_address: str, listen_port: str):
    try:
        resolver = Resolver(listen_address, int(listen_port))
        address, port = resolver.start()
        pid = os.getpid()
        with open(SEEKER_PID_FILEPATH, 'w') as fout:
            fout.write(f'{pid}\t{address}\t{port}\n')
        assert resolver.thread
        resolver.thread.join()
    except KeyboardInterrupt:
        LOGGER.info('caught SIGINT.')
    finally:
        os.unlink(SEEKER_PID_FILEPATH)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
