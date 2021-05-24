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
import logging.handlers
from pathlib import Path
from typing import List

from typer import get_app_dir


def get_logger(name: str, app_dir: str = "", file_prefix: str = ""):
    return MetemcyberLogger(name=name, app_dir=app_dir,
                            file_prefix=file_prefix).logger


class MetemcyberLogger():
    """
    Class for logging metemcyber Clis
    """
    created_loggers: List[str] = []

    def __init__(self, name: str, app_dir: str = "",
                 file_prefix: str = "") -> None:
        """Initilizates a Logger for Metemcyber Clis.

        :param name: Strings of logger name.
        :param log_file: Strings of log file name.
        :param log_level: Strings of Log level.
        """

        # The default location
        app_default_dir = get_app_dir("metemcyber")
        # Max bytes of log file
        max_bytes: int = 32768000
        # The number of backup of log file
        backup_num: int = 3

        # If already registered, return logger
        if name in MetemcyberLogger.created_loggers:
            self.logger: logging.Logger = logging.getLogger(name)
        else:
            # Use a directory of this app
            if not app_dir:
                app_dir = app_default_dir
            log_path: Path = Path(app_dir) / "logs"
            log_path.mkdir(parents=True, exist_ok=True)

            # Setup Logger
            self.logger = logging.getLogger(name)
            self.logger.setLevel(logging.DEBUG)

            user_formatter = UserFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            # Set log file name
            if file_prefix != "":
                error_filename = f"{file_prefix}-error.log"
                debug_filename = f"{file_prefix}-debug.log"
            else:
                error_filename = "error.log"
                debug_filename = "debug.log"

            # Setup error log file handler
            rth_error = logging.handlers.RotatingFileHandler(
                filename=log_path / error_filename,
                maxBytes=max_bytes,
                backupCount=backup_num,
            )
            rth_error.setLevel(logging.WARNING)
            rth_error.setFormatter(user_formatter)
            self.logger.addHandler(rth_error)

            # Setup debug log file handler
            rth_debug = logging.handlers.RotatingFileHandler(
                filename=log_path / debug_filename,
                maxBytes=max_bytes,
                backupCount=backup_num,
            )
            rth_debug.setLevel(logging.DEBUG)
            rth_debug.setFormatter(formatter)
            self.logger.addHandler(rth_debug)

            MetemcyberLogger.created_loggers.append(name)


class UserFormatter(logging.Formatter):
    def formatException(self, _):
        # TODO: StackTrace発生時、ユーザーに通知したいコメントを書く
        return None
