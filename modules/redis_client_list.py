# Copyright (c) 2018-2020 The Mode Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy


def Parse(text, command_data):
    """Parse the output of our command and prepare for export as list of dicts."""
    data = []

    '''
    id=10115 addr=10.0.1.137:48584 fd=17 name= age=44857 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=publish
    id=4945 addr=10.0.2.17:58154 fd=11 name= age=6023458 idle=5331841 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=publish
    id=10112 addr=10.0.1.137:36896 fd=12 name= age=44933 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=32768 obl=0 oll=0 omem=0 events=r cmd=publish
    id=10113 addr=10.0.1.137:36898 fd=13 name= age=44933 idle=0 flags=N db=0 sub=2 psub=1 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=subscribe
    id=10114 addr=10.0.1.137:48610 fd=15 name= age=44868 idle=0 flags=N db=0 sub=2 psub=1 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=subscribe
    id=3025 addr=10.0.1.233:58050 fd=16 name= age=8714816 idle=8338037 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=publish
    id=10167 addr=10.0.0.49:58262 fd=10 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=32768 obl=0 oll=0 omem=0 events=r cmd=client
    '''

    lines = text.split('\n')

    for line in lines:
        item = {}

        try:
            # Get a dictionary of data from this line
            line_data = {}
            parts = line.split(' ')
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    line_data[key] = value

            # Skip empties
            if not line_data:
                continue

            # print 'Line Data: %s' % line_data

            # Create the labelset from our defaults
            item['labelset'] = {}
            for key, value in command_data['labelset'].items():
                item['labelset'][key] = value

            # Add in custom labelset values from our line_data.  This is used for all metrics.  Changes can be added per metric after the copy.deepcopy() below
            item['labelset']['cmd'] = line_data['cmd']
            item['labelset']['addr'] = line_data['addr'].split(':')[0]


            # Make a deep copy for each item, so we can add unique metrics from our common labelset -- Repeat for each metric
            metric = 'omem'
            metric_item = copy.deepcopy(item)
            metric_item['metric'] = '%s_%s' % (command_data['metric_prefix'], metric)
            metric_item['help'] = '%s %s' % (metric_item['metric'], metric)
            metric_item['type'] = '%s gauge' % metric_item['metric']
            metric_item['value'] = line_data['omem']
            data.append(metric_item)

        except Exception, e:
            # Catch them all!
            # print 'Parse error: %s' % e
            pass

    return data

