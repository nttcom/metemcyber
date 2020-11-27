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

from ctitoken import CTIToken
from ctioperator import CTIOperator

TASK_STATES = ['Pending', 'Accepted', 'Finished', 'Cancelled']


class Seeker():
    def __init__(self, contracts):
        self.contracts = contracts

    def challenge(self, operator_address, token_address, data=''):
        # tokenをoperatorに送信
        # operatorデプロイ時にrecipientFor実行し、token受領時の動作設定済
        tx_receipt = self.contracts.accept(CTIToken()).get(token_address).\
            send_token(operator_address, data=data)
        if tx_receipt['status'] != 1:
            return False
        return True

    def cancel_challenge(self, operator_address, task_id):
        operator = self.contracts.accept(CTIOperator()).get(operator_address)
        operator.cancel_challenge(task_id)

    def list_tasks(self, operator_address, catalog=None):
        operator = self.contracts.accept(CTIOperator()).get(operator_address)
        raw_tasks = []
        limit_atonce = 16
        offset = 0
        while True:
            tmp = operator.history('0x{:040x}'.format(0), limit_atonce, offset)
            raw_tasks.extend(tmp)
            if len(tmp) < limit_atonce:
                break
            offset += limit_atonce

        tasks = dict()
        for (task_id, token, solver, seeker, state) in reversed(raw_tasks):
            try:
                title = catalog[token]['title']
            except:
                title = '(no information found on current catalog)'
            tasks[task_id] = {
                'token': token, 'title': title, 'solver': solver,
                'seeker': seeker, 'state': TASK_STATES[state]}
        return tasks
