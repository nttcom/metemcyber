#
#    Copyright 2020, NTT Communications Corp.
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

import json
import argparse
import pymisp


def _has_ids_flag(objects_list):
    return any([attribute['to_ids'] for attribute in objects_list])
    
def _has_ttp_galaxy(galaxies_list):
    TTP_TYPE = ['mitre-attack-pattern']
    return any([galaxy['type'] in TTP_TYPE
                for galaxy in galaxies_list])

def _has_custom_rule(objects_list):
    CUSTOME_RULE = ['yara', 'zeek']
    return any([attribute['type'] in CUSTOME_RULE for attribute in objects_list])

def validate_event(event_json):
    has_ioc = False
    has_ttp = False
    has_rule = False


    # MISP Event形式の判定
    event_dict = event_json.get('Event')
    if event_dict is None or event_dict.get('info') is None:
        return {'MISPEvent': False}
    else:
        result = {'MISPEvent': True}
        # IOCの判断 -> to_ids flagの有無
        has_ioc = _has_ids_flag(event_dict['Attribute'])

        for obj in event_dict['Object']:
            has_ioc = has_ioc or _has_ids_flag(obj['Attribute'])
        
        # TTPs framework
        has_ttp = _has_ttp_galaxy(event_dict['Galaxy'])

        # Custom ruleの判断 -> yara, zeek
        has_rule = _has_custom_rule(event_dict['Attribute'])
        for obj in event_dict['Object']:
            has_rule = has_rule or _has_custom_rule(obj['Attribute'])

        result['content'] = {
            'IOC': has_ioc,
            'TTP': has_ttp,
            'Rule': has_rule
        }
        return result
    

if __name__ == '__main__':

    # to use proxy, set environment variable HTTP_PROXY or HTTPS_PROXY.
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', type=argparse.FileType('r'))
    args = parser.parse_args()
    event_json = json.load(args.infile)
    validate_result = validate_event(event_json)
    
    if validate_result['MISPEvent']:
        print('The content of MISP Event file:')
        print('IOC:', 'Exist' if validate_result['content']['IOC'] else 'Not Exist')
        print('TTPs:', 'Exist' if validate_result['content']['TTP'] else 'Not Exist')
        print('Custome Rule:', 'Exist' if validate_result['content']['Rule'] else 'Not Exist')
    else:
        print('File does not meet MISP Event requirements.')
