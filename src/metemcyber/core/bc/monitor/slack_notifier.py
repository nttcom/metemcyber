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

import argparse
import json
import sys
from argparse import Namespace
from typing import ClassVar, List, Tuple, Type

import requests

from metemcyber.core.bc.monitor.tx_counter import str2counter


class SectionGenerator:
    def summary_to_sections(self, summary: dict, _args: Namespace, _options: dict) -> List[dict]:
        return [{
            'fallback': self.__class__.__name__,
            'title': 'abstract generator',
            'text': str(summary),
        }]


class Waixu(SectionGenerator):
    colormap: ClassVar[List[str]] = [
        '#CC0000', '#CC2200', '#CC4400', '#CC6600', '#CC8800', '#CC9900',
        '#CCAA00', '#CCBB00', '#CCCC00', '#99CC00', '#00CC00', '#00CCCC',
    ]

    @staticmethod
    def _calc_waicu(summary: dict) -> Tuple[int, str]:
        if not summary.get('waicu'):
            sold = []
            num_sold = waicu = 0
        else:
            sold = sorted(
                [(catalog,
                  sum(val['tokens'].values()),
                  len(val['buyers']),
                  sorted(list(val['tokens'].items()), key=lambda x:x[1], reverse=True)
                  )
                 for catalog, val in summary['waicu'].items() if catalog != 'total'
                 ],
                reverse=True)
            total = summary['waicu']['total']
            waicu = len(total['buyers'].keys())
            num_sold = sum(total['tokens'].values())

        text = ''
        if len(sold) > 0:
            text = (f'*{num_sold} token{"s" if num_sold > 1 else ""} sold' +
                    f' on {len(sold)} catalog{"s" if len(sold) > 1 else ""}' +
                    f' by {waicu} buyer{"s" if waicu > 1 else ""}' +
                    '*\n')
            for catalog, num_sold, num_buyers, tokens in sold:
                text += f'\tCatalog: `{catalog}`\n'
                text += f'\t\tsold tokens (total: {num_sold}, buyer: {num_buyers})\n'
                for token, num in tokens:
                    text += f'\t\t\t{num} : {token}\n'

        return waicu, text

    @staticmethod
    def _calc_waipu(summary: dict) -> Tuple[int, str]:
        if not summary.get('waipu'):
            pubed = []
            waipu = num_pubed = num_unreg = 0
        else:
            pubed = sorted(
                [(catalog,
                  sum(val.get('publish', {'0': 0}).values()),
                  len(val.get('publish', {'0': 0})),
                  sum(val.get('unregister', {'0': 0}).values())
                  )
                 for catalog, val in summary['waipu'].items() if catalog != 'total'
                 ],
                reverse=True)
            total = summary['waipu']['total']
            waipu = len(total.get('publish', {}).keys())
            num_pubed = sum(total.get('publish', {}).values())
            num_unreg = sum(total.get('unregister', {}).values())

        text = ''
        if len(pubed) > 0:
            text = (f'*{num_pubed} token{"s" if num_pubed > 1 else ""} published' +
                    (f' (and unpublished {num_unreg})' if num_unreg > 0 else '') +
                    f' on {len(pubed)} catalog{"s" if len(pubed) > 1 else ""}' +
                    '*\n')
            for catalog, n_pubed, n_puber, n_unreg, in pubed:
                text += f'\tcatalog: `{catalog}`\n'
                text += f'\t\tpublished: {n_pubed}, '
                text += f'unpublish: {n_unreg}, ' if n_unreg > 0 else ''
                text += f'publisher: {n_puber}\n'

        return waipu, text

    def summary_to_sections(self, summary: dict, _args: Namespace, _options: dict) -> List[dict]:
        waicu, waicu_text = self._calc_waicu(summary)
        waipu, waipu_text = self._calc_waipu(summary)

        title = f'WAICU={waicu}, WAIPU={waipu}'
        text = waicu_text + waipu_text
        score = min(int((waicu + waipu) / 2), len(Waixu.colormap) - 1)
        color = Waixu.colormap[score]

        return [{
            'fallback': title,
            'color': color,
            'title': title,
            'text': text,
        }]


class SlackNotifier:
    conf: dict
    sections: List[dict]
    testmode: bool

    def __new__(cls, *_args, **_kwargs):
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_filepath: str, testmode: bool = False):
        if hasattr(self, 'conf') and self.conf:
            return
        with open(config_filepath, 'r') as fin:
            self.conf = json.load(fin).get('slack_notifier', {})
        for key in {'webhook', 'channel', 'appname'}:
            if key not in self.conf.keys():
                raise Exception(f'ConfigError: Missing {key}')
        self.sections = []
        self.testmode = testmode

    def add_sections(self, sections):
        if sections:
            self.sections.extend(sections)

    def send_query(self):
        if not self.sections:
            print('nothing to send. skip sending query.')
            return

        headers = {
            'Content-type': 'application/json',
        }
        payload = {
            'channel': self.conf['channel'],
            'username': self.conf['appname'],
            'attachments': self.sections,
        }
        if self.testmode:
            print('__TestMode__')
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return

        print(f'sending query to: {self.conf["webhook"]}', file=sys.stderr)
        response = requests.post(
            self.conf['webhook'],
            headers=headers,
            data=json.dumps(payload, ensure_ascii=False).encode('utf-8'))
        print(response.text)


def str2generator(classname: str) -> Type[SectionGenerator]:
    generator_class = (Waixu if classname == 'Waixu' else
                       SectionGenerator if classname == 'Simple' else
                       None)
    if not generator_class:
        raise Exception(f'Invalid Generator classname: {classname}')
    return generator_class


def _gen_options(args: Namespace, options: dict) -> dict:
    for key in {'start', 'end', 'date_format'}:
        if getattr(args, key, None):
            options[key] = getattr(args, key)
    return options


def main(args: Namespace):
    notifier = SlackNotifier(args.config, testmode=args.testmode)
    with open(args.config, 'r') as fin:
        queries = [q for q in json.load(fin).get('queries', []) if not q.get('disable')]
    for query in queries:
        generator = str2generator(query['class'])()
        options = _gen_options(args, query.get('options', {}))
        if args.remote:
            summary = requests.post(
                args.remote,
                data=json.dumps([query], ensure_ascii=False).encode()
            ).json()[0]
        else:
            counter = str2counter(query['class'])(args, options)
            summary = counter.summarize(args, options)
        notifier.add_sections(generator.summary_to_sections(summary, args, options))
    notifier.send_query()


OPTIONS: List[Tuple[str, str, dict]] = [
    ('-c', '--config', dict(action='store', required=True)),
    ('-t', '--testmode', dict(action='store_true', required=False)),
    ('-d', '--date_format', dict(action='store', required=False)),
    ('-s', '--start', dict(action='store', required=False)),
    ('-e', '--end', dict(action='store', required=False)),
    ('-r', '--remote', dict(action='store', required=False, help='query service url')),
]

ARGUMENTS: List[Tuple[str, dict]] = [
]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, opts in OPTIONS:
        PARSER.add_argument(sname, lname, **opts)
    for name, opts in ARGUMENTS:
        PARSER.add_argument(name, **opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
