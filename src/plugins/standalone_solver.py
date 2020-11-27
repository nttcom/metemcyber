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

import logging
from threading import Thread
from socketserver import TCPServer
from http.server import SimpleHTTPRequestHandler
from web3 import Web3
from solver import BaseSolver
from client_model import FILESERVER_ASSETS_PATH

LOGGER = logging.getLogger('common')

JOIN_TIMEOUT_SEC = 30
LISTEN_ADDR = ''
LISTEN_PORT = 50080
CONTENTS_ROOT = FILESERVER_ASSETS_PATH


class SimpleHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args):
        self.logpref = 'LocalHttpServer'
        SimpleHTTPRequestHandler.__init__(self, *args, directory=CONTENTS_ROOT)

    def do_GET(self):
        SimpleHTTPRequestHandler.do_GET(self)

    def log_error(self, *args):
        LOGGER.error(self.logpref+': '+args[0], *args[1:])

    def log_message(self, *args):
        LOGGER.info(self.logpref+': '+args[0], *args[1:])


class LocalHttpServer():

    def __init__(self, identity):
        self.identity = identity
        self.thread = None
        self.server = None
        self.addr = LISTEN_ADDR
        self.port = LISTEN_PORT
        self.handler = SimpleHandler

    def start(self):
        if self.thread:
            return
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        LOGGER.info(
            '%s: starting httpd: %s', self.__class__.__name__, self.identity)
        with TCPServer((self.addr, self.port), self.handler) as httpd:
            self.server = httpd
            httpd.serve_forever()
        LOGGER.info(
            '%s: stopped httpd: %s', self.__class__.__name__, self.identity)

    def stop(self):
        if not self.thread or not self.server:
            return
        self.server.shutdown()
        self.thread.join(timeout=JOIN_TIMEOUT_SEC)
        if self.thread and self.thread.is_alive():
            LOGGER.error('failed stopping httpd: %s', self.identity)
            return
        self.thread = self.server = None


class Solver(BaseSolver):

    def __init__(self, *args):
        super().__init__(*args)
        operator_address = args[2]
        self.fileserver = LocalHttpServer(operator_address)
        self.fileserver.start()

    def destroy(self):
        if self.fileserver:
            self.fileserver.stop()
            self.fileserver = None
        super().destroy()

    def process_challenge(self, token_address, event):
        LOGGER.info('Solver: callback: %s', token_address)
        LOGGER.debug(event)
        try:
            task_id = event['args']['taskId']
            challenge_seeker = event['args']['from']
            LOGGER.info(
                'accepting task %s from seeker %s', task_id, challenge_seeker)
            if not self.accept_task(task_id):
                LOGGER.info('could not accept task %s', task_id)
                return
            LOGGER.info('accepted task %s', task_id)
        except Exception as err:
            LOGGER.exception(err)
            return

        data = ''
        try:
            # process for Demo
            download_url = self.create_misp_download_url(
                self.account_id, token_address)
            url = Web3.toText(event['args']['data'])

            # return answer via webhook
            LOGGER.info('returning answer to %s', url)
            self.webhook(url, download_url, token_address)
        except Exception as err:
            data = str(err)
            LOGGER.exception(err)
            LOGGER.error('failed task %s', task_id)
        finally:
            self.finish_task(task_id, data)
            LOGGER.info('finished task %s', task_id)

    @staticmethod
    def create_misp_download_url(account_id, cti_address):
        url = 'http://{host}:{port}/{path}'.format(
            host=account_id, port=LISTEN_PORT, path=cti_address)
        return url
