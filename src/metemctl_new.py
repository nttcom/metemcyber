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
import yaml

CONFIG_YML_FILEPATH = 'kedro.yml'


# インテリジェンスサイクルに使う新規プロジェクトを作成
def create_project():
    project_id = str(uuid.uuid4())

    with open(CONFIG_YML_FILEPATH) as fin:
        config = yaml.safe_load(fin)

    # TODO: MISPオブジェクトのタイトルをproject_nameに利用
    config['project_name'] = project_id
    config['repo_name'] = project_id
    config['python_package'] = "metemcyber_" + project_id.replace('-', '_')

    with open(CONFIG_YML_FILEPATH, 'w') as fout:
        yaml.dump(config, fout)

    call(['kedro', 'new', '--config', CONFIG_YML_FILEPATH])
    print(project_id, 'create successful.')
    return project_id

if __name__ == '__main__':
    project_id = create_project()
    # 新規ワークフローをactiveにする
    exit(call(['python', 'src/metemctl_config.py', 'config', 'set', 'project', project_id]))
