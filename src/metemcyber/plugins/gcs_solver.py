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

import json
import os
from json.decoder import JSONDecodeError
from typing import Optional

import requests
from eth_typing import ChecksumAddress
from web3 import Web3

from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.logger import get_logger
from metemcyber.core.solver import BaseSolver
from metemcyber.core.util import merge_config

LOGGER = get_logger(name='gcs_solver', file_prefix='core')

CONFIG_SECTION = 'gcs_solver'
DEFAULT_CONFIGS = {
    CONFIG_SECTION: {
        'assets_path': f'{APP_DIR}/workspace/upload',
        'functions_url': 'https://exchange.metemcyber.ntt.com',
        'functions_token': 'YOUR_TOKEN_TO_UPLOAD_GCS',
    }
}
# Note: assets_path should be same with "{general.workspace}/upload".


class Solver(BaseSolver):
    def __init__(self, account: Account, operator_address: ChecksumAddress,
                 config_file: Optional[str]) -> None:
        super().__init__(account, operator_address)
        self.config = merge_config(config_file, DEFAULT_CONFIGS, self.config)
        try:
            url = self.config[CONFIG_SECTION]['functions_url']
            token = self.config[CONFIG_SECTION]['functions_token']
            assert url and token not in (
                None, '', DEFAULT_CONFIGS[CONFIG_SECTION]['functions_token'])
        except Exception as err:
            raise Exception('Not enough configuration to upload to GCS') from err
        self.uploader = Uploader(url, token)

    def notify_first_accept(self):
        url = self.config[CONFIG_SECTION]['functions_url']
        return f'Caution: solved challenge data will be uploaded onto {url}.'

    def process_challenge(self, token_address, event):
        LOGGER.info('GCSSolver: callback: %s', token_address)
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
            try:
                download_url = self.upload_to_storage(token_address)
                webhook_url = Web3.toText(event['args']['data'])
            except Exception:
                data = 'Challenge failed by solver side error'
                raise
            try:
                # return answer via webhook
                self.webhook(webhook_url, download_url, challenge_seeker, task_id, token_address)
            except Exception as err:
                data = 'cannot sendback result via webhook: ' + str(err)
                raise
        except Exception as err:
            LOGGER.exception(err)
            LOGGER.error('failed task %s', task_id)
        finally:
            self.finish_task(task_id, data)
            LOGGER.info('finished task %s', task_id)

    def upload_to_storage(self, cti_address):
        file_path = os.path.abspath('{}/{}'.format(
            self.config.get(CONFIG_SECTION, 'assets_path'), cti_address))
        url = self.uploader.upload_file(file_path)
        return url


class Uploader:
    def __init__(self, url: str, functions_token: str) -> None:
        assert url
        assert functions_token
        self.url = url
        self.functions_token = functions_token

    def upload_file(self, upload_path: str) -> str:
        headers = {
            'Authorization': 'Bearer {}'.format(self.functions_token),
            'Content-Type': 'application/json'}
        try:
            # Note: gcs(exchange.metemcyber.ntt.com) accepts json data only.
            with open(upload_path, 'r') as fin:
                jdata = json.load(fin)
        except Exception as err:
            raise Exception(f'Not a expected data format: {upload_path}') from err
        response = requests.post(
            self.url,
            json=jdata,
            headers=headers)
        try:
            results = response.json()
        except JSONDecodeError as err:
            LOGGER.debug(response.headers)
            LOGGER.debug(response.text[:256])
            raise Exception(f'Received unexpected (not a JSON) result: {err}') from err
        if 'result' in results:
            return results['result']  # OK
        raise Exception('File upload failed: ' + results['error'])
