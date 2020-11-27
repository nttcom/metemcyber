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
import os
from urllib.parse import urlparse
from threading import Thread
from flask import Flask, request

LOGGER = logging.getLogger('common')


APP = Flask(__name__)

@APP.route('/', methods=['POST'])
def webhook_receiver():
    # curl -X POST -H "Content-Type: application/json" \
    #      -d '{"result":"this_answer_output_by_solver"}' 127.0.0.1:12345/
    # resultキーがあれば表示
    data = request.get_json()

    # callbackの通知
    if WebhookReceiver.callback:
        WebhookReceiver.callback(data)
        return 'webhook received.'
    return 'There are no waiting process'


class WebhookReceiver():
    thread = None
    callback = None
    baseurl = None

    def __new__(cls, *_args, **_kargs):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        pass

    @classmethod
    def start(cls, url):
        if WebhookReceiver.thread:
            return
        logging.getLogger('werkzeug').disabled = True
        os.environ['WERKZEUG_RUN_MAIN'] = 'true'
        LOGGER.info('Running on %s', url)
        cls.baseurl = url

        obj = urlparse(url)
        WebhookReceiver.thread = Thread(
            target=APP.run,
            kwargs={'host':obj.hostname, 'port':obj.port},
            daemon=True)
        WebhookReceiver.thread.start()

    @classmethod
    def set_callback(cls, callback):
        cls.callback = callback

    @classmethod
    def get_url(cls, token_address):
        assert cls.baseurl
        assert token_address
        # TODO should generate individual url for each token?
        return cls.baseurl
