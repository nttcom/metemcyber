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
import pathlib
import logging
import logging.handlers
from typing import Literal

import typer

LOG_LEVEL = Literal['error', 'warning', 'info', 'debug']

class MetemcyberLogger():
    """
    Class for logging metemcyber Clis
    """

    def __init__(self, name: str, log_file: str, log_level: LOG_LEVEL) -> None:
        """Initilizates a Logger for Metemcyber Clis.

        :param name: Strings of logger name.
        :param log_file: Strings of log file name.
        :param log_level: Strings of Log level.
        """
        # Application name
        APP_NAME: str = "metemcyber"
        # Max bytes of log file
        MAX_BYTES: int = 32768000
        # The number of backup of log file 
        BACKUP_NUM: int = 3

        # Get app directory
        app_dir: str = typer.get_app_dir(APP_NAME)
        log_path: pathlib.Path = pathlib.Path(app_dir) / "log"
        log_path.mkdir(parents=True, exist_ok=True)

        # Setup Logger
        self.logger: logging.Logger = logging.getLogger(name)

        level_map: dict = {
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'info': logging.INFO,
            'debug': logging.DEBUG
        }

        # Setup RatatingFileHandler
        rth = logging.handlers.RotatingFileHandler(
            filename = log_path / log_file,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_NUM,
        )
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        rth.setFormatter(formatter)
        self.logger.addHandler(rth)

        # Set log level
        self.logger.setLevel(level_map[log_level])
