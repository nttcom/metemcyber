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
usage:  metemctl config get [options] <key>
        metemctl config set [options] <key> <value>
        metemctl config list [options]

    -h, --help
    -s, --section <name>

"""
from docopt import docopt
import configparser

CONFIG_INI_FILEPATH = "metemctl.ini"


if __name__ == '__main__':

    args = docopt(__doc__)
        
    config = configparser.ConfigParser()
    config.add_section('general')
    config.read(CONFIG_INI_FILEPATH)

    if args['--section']:
        section = args['--section']
    else:
        section = 'general'

    # get value from key
    if args['get']:
        key = args['<key>']
        if config.has_option('general', key):
            print(config['general'][key])
        else:
            print('Not a valid key: {0}'.format(key))
    # set key=value
    elif args['set']:
        key = args['<key>']
        value = args['<value>']
        if config.has_option('general', key):
            config.set('general', key, value)
            with open(CONFIG_INI_FILEPATH, 'w') as fout:
                config.write(fout)
                print('update config.')
        else:
            print('Not a valid key: {0}'.format(key))
    # print all option values
    elif args['list']:
        for option in config[section]:
            print(option, ":", config[section][option])
    else:
        exit("Options are not set. See 'metemctl config --help'.")
