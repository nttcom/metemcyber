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

import typer

APP_NAME = "metemcyber"
MAX_BYTES = 8192000
BACKUP_NUM = 3
LOGNAME = 'metemcyber.log'


def setup_logger(name: str) -> logging.Logger:
    # If there is no 
    app_dir = typer.get_app_dir(APP_NAME)
    log_path: Path = Path(app_dir) / "log"
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    
    # RatatingFileHandler
    rth = logging.handlers.RotatingFileHandler(
        filename= log_path / LOGNAME,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_NUM,
    )
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    rth.setFormatter(formatter)
    logger.addHandler(rth)

    return logger
