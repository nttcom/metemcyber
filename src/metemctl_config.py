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
usage: metemctl config <command> [<target>] [<value>]

options:
   -h, --help

"""
from docopt import docopt
import configparser

CONFIG_INI_FILEPATH = "metemctl.ini"


if __name__ == '__main__':

    args = docopt(__doc__,
                  options_first=True)
    
    config = configparser.ConfigParser()
    config.add_section('general')
    config.read(CONFIG_INI_FILEPATH)
    
    do = args['<command>']
    target = args['<target>']
    value = args['<value>']

    # get command
    if do == "get":
        if target:
            print(config['general'][target])
        else:
            print("Please specify the <target> in the 'get' command. See 'metemctl config --help'.")
    # set command
    elif do == "set" and target:
        if target and value:
            config.set('general', target, value)
            with open(CONFIG_INI_FILEPATH, 'w') as fout:
                config.write(fout)
                print('update config.')
        else:
            print("Please specify the <target> and <value> in the 'set' command. See 'metemctl config --help'.")
    # list command
    elif do == "list":
        for option in config['general']:
            print(option, ":", config['general'][option])
    else:
        exit("%r is not valid in the config command. See 'metemctl config --help'." % args['<command>'])
