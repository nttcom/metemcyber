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

# See https://packaging.python.org/

import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))


def load_requirements(filename):
    with open(os.path.join(here, 'requirements', filename)) as fin:
        requirements = fin.read().splitlines()
    return requirements


extras_require = {}
extras_require['cli'] = load_requirements('tools.txt')
extras_require['test'] = load_requirements('test.txt')
extras_require['doc'] = load_requirements('docs.txt')
extras_require['dev'] = extras_require['test'] + extras_require['doc']
extras_require['all'] = extras_require['cli'] + extras_require['dev']

setup(
    install_requires=load_requirements('common.txt'),
    extras_require=extras_require,
    tests_require=extras_require['test']
)
