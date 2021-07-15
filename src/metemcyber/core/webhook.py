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

import logging
import os
import sys
from threading import Thread
from time import sleep
from typing import Callable, Optional, Tuple

from flask import Flask, request
from werkzeug.datastructures import EnvironHeaders

from .util import get_random_local_port

RANDOM_PORT_RETRY_MAX = 10

os.environ['WERKZEUG_RUN_MAIN'] = 'true'  # eliminate werkzeug server banner on boot
logging.getLogger('werkzeug').disabled = True


class WebhookReceiver():
    def __init__(self, address: str, port: int,
                 callback: Optional[Callable[[EnvironHeaders, str], None]] = None) -> None:
        assert port >= 0
        self.address: str = address
        self.port: int = port
        self.callback: Callable[[EnvironHeaders, str],
                                None] = callback if callback else self.resolve_request
        self.thread: Optional[Thread] = None

    def start(self) -> Tuple[str, int]:
        if self.thread:
            raise Exception('Already running')
        self.thread = Thread(target=self.boot_server, daemon=True)
        self.thread.start()
        sleep(1)
        assert self.thread
        assert self.thread.is_alive()
        return self.address, self.port

    def boot_server(self) -> None:
        app = Flask(self.__class__.__name__)
        app.add_url_rule('/', 'post_callback', self._data_dispatcher, methods=['POST'])
        if self.port > 0:
            app.run(self.address, self.port)
            return
        retry = RANDOM_PORT_RETRY_MAX
        while True:
            try:
                self.port = get_random_local_port()
                app.run(self.address, self.port)
            except OSError as err:
                if err.errno == 98:  # Address already in use
                    retry -= 1
                    if retry > 0:
                        continue
                    raise Exception('Cannot get unused port') from err
            break
        self.thread = None

    def _data_dispatcher(self) -> str:
        headers = request.headers
        body = request.get_data(cache=False, as_text=True)  # XXX: should decode as text?
        Thread(target=self.callback, args=[headers, body], daemon=True).start()
        return 'ok'

    def resolve_request(self, headers: EnvironHeaders, body: str) -> None:
        print(self)
        print(headers)
        print('--')
        print(body)


def main(listen_address: str, listen_port: str):
    try:
        webhook = WebhookReceiver(listen_address, int(listen_port))
        address, port = webhook.start()
        pid = os.getpid()
        print(f'{pid}\t{address}\t{port}')
        assert webhook.thread
        webhook.thread.join()
    except KeyboardInterrupt:
        print('caught SIGINT.')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
