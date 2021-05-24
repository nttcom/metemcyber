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

import os
from signal import SIGINT
from subprocess import Popen, TimeoutExpired
from tempfile import mkstemp
from time import sleep
from typing import Optional, Tuple

import requests
from psutil import NoSuchProcess, Process

from metemcyber.core.logger import get_logger
from metemcyber.core.util import get_random_local_port, merge_config

LOGGER = get_logger(name='ngrok', file_prefix='core')

CONFIG_SECTION = 'ngrok'
DEFAULT_CONFIGS = {
    CONFIG_SECTION: {
        'ngrok_path': 'ngrok',
        'ngrok_web_port': '0',
    }
}


def ngrok_pid_filepath(app_dir: str) -> str:
    return f'{app_dir}/ngrok.pid'


class NgrokMgr():
    def __init__(self, app_dir: str, seeker_port: int = 0, config_path: Optional[str] = None
                 ) -> None:
        self.app_dir: str = app_dir
        self.seeker_port: int = seeker_port
        self.config = merge_config(config_path, DEFAULT_CONFIGS)
        self.ngrok_path: str = self.config[CONFIG_SECTION]['ngrok_path']
        pid, public_url = self.check_running()
        self.pid: int = pid
        self.public_url: Optional[str] = public_url

    def check_running(self) -> Tuple[int, Optional[str]]:  # (pid|0, public_url)
        pid_file = ngrok_pid_filepath(self.app_dir)
        try:
            with open(pid_file, 'r') as fin:
                str_data = fin.readline().strip()
            str_pid, public_url, str_saved_args = str_data.split('\t', 2)
            pid = int(str_pid)
            saved_args = str_saved_args.split('\t')
        except Exception:
            return 0, None
        try:
            proc = Process(pid)
            if proc.cmdline()[:len(saved_args)] == saved_args:
                return pid, public_url
            LOGGER.info(f'got pid({pid}) which is not a ngrok. remove defunct.')
            os.unlink(pid_file)
            return 0, None
        except NoSuchProcess:
            return 0, None

    @staticmethod
    def _get_public_url(port: int) -> str:
        query_url = f'http://localhost:{port}/api/tunnels/command_line'
        retry = 5
        last_error = None
        while retry > 0:
            try:
                sleep(1)
                response = requests.request('GET', query_url, timeout=1)
                return response.json()['public_url']
            except Exception as err:
                last_error = err
                retry -= 1
                continue
        raise Exception(f'Cannot get ngrok public_url: {last_error}')

    def _try_ngrok(self) -> Tuple[int, str]:
        web_port = int(self.config[CONFIG_SECTION]['ngrok_web_port'])
        retry = 1 if web_port > 0 else 10
        proc = None
        tmp_out, tmp_fname = mkstemp(suffix='.yml')
        try:
            os.close(tmp_out)
            args = [self.ngrok_path, 'http', '--config', tmp_fname, str(self.seeker_port)]
            while retry > 0:
                port = web_port if web_port else get_random_local_port()
                with open(tmp_fname, 'w') as fout:
                    fout.write('console_ui: false\n'
                               f'web_addr: localhost:{port}\n')
                # ngrok needs to keep running in the background
                # pylint pylint: disable=R1732
                proc = Popen(args, shell=False)
                try:
                    proc.wait(timeout=1)  # may exit with 'Address already in use'
                    del proc
                    proc = None
                    retry -= 1
                    continue
                except TimeoutExpired:  # ok
                    break
            if retry == 0:
                raise Exception('Failed launching ngrok')
            public_url = self._get_public_url(port)
            with open(ngrok_pid_filepath(self.app_dir), 'w') as fout:
                assert proc
                fout.write('\t'.join([str(proc.pid), public_url] + args))
            return proc.pid, public_url
        except Exception:
            if proc:
                proc.kill()
            raise
        finally:
            os.unlink(tmp_fname)

    def start(self) -> None:
        """launch Ngrok as another process
        """
        if self.pid:
            raise Exception(f'Already running on pid({self.pid}).')
        assert self.seeker_port > 0
        self.pid, self.public_url = self._try_ngrok()
        LOGGER.info(f'started. pid={self.pid}, public_url={self.public_url}.')

    def stop(self) -> None:
        if not self.pid:
            raise Exception('Not running')
        try:
            LOGGER.info(f'stopping process({self.pid}).')
            os.kill(self.pid, SIGINT)
            os.unlink(ngrok_pid_filepath(self.app_dir))
            self.pid = 0
        except Exception as err:
            raise Exception(f'Cannot stop ngrok(pid={self.pid})') from err
