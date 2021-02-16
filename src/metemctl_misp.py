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
usage: metemctl misp [options] <command>

options:
   -h, --help

"""
from docopt import docopt
import configparser
from subprocess import call

CONFIG_INI_FILEPATH = "metemctl.ini"


if __name__ == '__main__':

    args = docopt(__doc__,
                  options_first=True)
    
    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)
    
    do = args['<command>']
    if do == "access":
        path = config['general']["browser_path"]
        url = config['general']["misp_url"]
        exit(call([path, url]))
    else:
        exit("%r is not valid in the config command. See 'metemctl config --help'." % args['<command>'])
