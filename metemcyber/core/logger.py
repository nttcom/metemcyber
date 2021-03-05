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
from typing import List

import typer


class MetemcyberLogger():
    """
    Class for logging metemcyber Clis
    """
    created_loggers: List[str] = []

    def __init__(self, name: str) -> None:
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

        # If already registered, return logger
        if name in MetemcyberLogger.created_loggers:
            self.logger = logging.getLogger(name)
        else:
            # Get app directory
            app_dir: str = typer.get_app_dir(APP_NAME)
            log_path: pathlib.Path = pathlib.Path(app_dir) / "log"
            log_path.mkdir(parents=True, exist_ok=True)

            # Setup Logger
            self.logger: logging.Logger = logging.getLogger(name)
            self.logger.setLevel(logging.DEBUG)

            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            # Setup error log file handler
            rth_error = logging.handlers.RotatingFileHandler(
                filename = log_path / 'error.log',
                maxBytes=MAX_BYTES,
                backupCount=BACKUP_NUM,
            )
            rth_error.setLevel(logging.WARNING)
            rth_error.setFormatter(formatter)
            self.logger.addHandler(rth_error)

            # Setup debug log file handler
            rth_debug = logging.handlers.RotatingFileHandler(
                filename = log_path / 'debug.log',
                maxBytes=MAX_BYTES,
                backupCount=BACKUP_NUM,
            )
            rth_debug.setLevel(logging.DEBUG)
            rth_debug.setFormatter(formatter)
            self.logger.addHandler(rth_debug)

            MetemcyberLogger.created_loggers.append(name)
