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

"""
usage: metemctl new

options:
   -h, --help

"""
from subprocess import call
from docopt import docopt
import uuid
import os

# インテリジェンスサイクルに使う新規ワークフローを作成
def create_workflow():
    workflow_id = str(uuid.uuid4())
    print(workflow_id)
    os.makedirs(workflow_id, exist_ok=True)
    print('successful')
    return workflow_id

if __name__ == '__main__':
    workflow_id = create_workflow()
    # 新規ワークフローをactiveにする
    exit(call(['python', 'src/metemctl_config.py', 'config', 'set', "workflow", workflow_id]))
