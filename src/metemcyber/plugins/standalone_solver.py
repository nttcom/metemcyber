#
#    Copyright 2020, NTT Communications Corp.
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

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from threading import Thread
from typing import ClassVar, Optional

from eth_typing import ChecksumAddress
from web3 import Web3

from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.logger import get_logger
from metemcyber.core.solver import BaseSolver
from metemcyber.core.util import get_random_local_port, merge_config

LOGGER = get_logger(name='standaone_solver', file_prefix='core')

GET_RANDOM_RETRY_MAX = 10
JOIN_TIMEOUT_SEC = 30

CONFIG_SECTION = 'standalone_solver'
DEFAULT_CONFIGS = {
    CONFIG_SECTION: {
        'listen_address': 'localhost',
        'assets_path': f'{APP_DIR}/workspace/upload',
    }
}
# Note: assets_path should be same with "{general.workspace}/upload".


class SimpleHandler(SimpleHTTPRequestHandler):
    assets_path: ClassVar[str] = ''  # Oops, is there smart way to set contents_root?

    def __init__(self, *args, **kwargs):
        assert SimpleHandler.assets_path
        self.logpref = 'LocalHttpServer'
        SimpleHTTPRequestHandler.__init__(
            self, *args, directory=SimpleHandler.assets_path, **kwargs)

    def do_GET(self):
        SimpleHTTPRequestHandler.do_GET(self)

    def log_error(self, *args):
        LOGGER.error(self.logpref + ': ' + args[0], *args[1:])

    def log_message(self, *args):
        LOGGER.info(self.logpref + ': ' + args[0], *args[1:])


class LocalHttpServer():
    def __init__(self, identity, addr, root):
        self.identity = identity
        self.thread = None
        self.server = None
        self.addr = addr
        self.port = 0
        self.assets_path = root
        self.handler = SimpleHandler

    def start(self):
        if self.thread:
            return
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        SimpleHandler.assets_path = self.assets_path
        for _count in range(GET_RANDOM_RETRY_MAX):
            try:
                self.port = get_random_local_port()
                LOGGER.info(
                    '%s: starting httpd: %s at %s:%d',
                    self.__class__.__name__, self.identity, self.addr, self.port)
                with TCPServer((self.addr, self.port), self.handler) as httpd:
                    self.server = httpd
                    httpd.serve_forever()
                LOGGER.info('%s: stopped httpd: %s', self.__class__.__name__, self.identity)
                return
            except OSError as err:
                if err.errno == 98:  # EADDRINUSE (address already in use)
                    continue
                raise
        raise Exception("cannot assign listen port for httpd")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=JOIN_TIMEOUT_SEC)
            if self.thread.is_alive():
                LOGGER.error('failed stopping httpd: %s', self.identity)
            self.thread = None


class Solver(BaseSolver):
    def __init__(self, account: Account, operator_address: ChecksumAddress,
                 config_path: Optional[str]) -> None:
        super().__init__(account, operator_address)
        self.config = merge_config(config_path, DEFAULT_CONFIGS, self.config)
        self.fileserver = LocalHttpServer(
            self.account.eoa,
            self.config[CONFIG_SECTION]['listen_address'],
            self.config[CONFIG_SECTION]['assets_path'])
        self.fileserver.start()

    def destroy(self):
        super().destroy()
        if self.fileserver:
            self.fileserver.stop()
            self.fileserver = None

    def process_challenge(self, token_address, event):
        LOGGER.info('StandaloneSolver: callback: %s', token_address)
        LOGGER.debug(event)

        task_id = event['args']['taskId']
        challenge_seeker = event['args']['from']
        LOGGER.info(
            'accepting task %s from seeker %s', task_id, challenge_seeker)
        if not self.accept_task(task_id):
            LOGGER.warning('could not accept task %s', task_id)
            return

        LOGGER.info('accepted task %s', task_id)
        data = ''
        try:
            # process for Demo
            download_url = self.create_misp_download_url(token_address)
            webhook_url = Web3.toText(event['args']['data'])

            # return answer via webhook
            LOGGER.info('returning answer to %s', webhook_url)
            self.webhook(webhook_url, download_url, challenge_seeker, task_id, token_address)
        except Exception as err:
            data = str(err)
            LOGGER.exception(err)
            LOGGER.error('failed task %s', task_id)
        finally:
            self.finish_task(task_id, data)
            LOGGER.info('finished task %s', task_id)

    def create_misp_download_url(self, cti_address):
        url = 'http://{host}:{port}/{path}'.format(
            host=self.config[CONFIG_SECTION]['listen_address'],
            port=self.fileserver.port,
            path=cti_address)
        return url
