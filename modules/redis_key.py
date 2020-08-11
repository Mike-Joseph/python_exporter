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
    (integer) 0
    '''

    # print 'redis_key: Parse Input: %s' % text

    lines = text.split('\n')

    for line in lines:
        item = {}

        try:
            # Get a dictionary of data from this line
            line_data = {}

            if ')' in line:
                parts = line.split(')', 1)
                line_data['value'] = float(parts[1])
            else:
                line_data['value'] = float(line.strip())

            # print 'Line Data: %s' % line_data

            # Create the labelset from our defaults
            item['labelset'] = {}
            for key, value in command_data['labelset'].items():
                item['labelset'][key] = value

            # Add in custom labelset values from our line_data.  This is used for all metrics.  Changes can be added per metric after the copy.deepcopy() below
            # item['labelset']['cmd'] = line_data['cmd']


            # Make a deep copy for each item, so we can add unique metrics from our common labelset -- Repeat for each metric
            metric = command_data['shell_vars']['redis_key']
            metric_item = copy.deepcopy(item)
            metric_item['metric'] = '%s_%s_%s' % (command_data['metric_prefix'], command_data['shell_vars']['redis_command'], metric)
            metric_item['help'] = '%s %s' % (metric_item['metric'], metric)
            metric_item['type'] = '%s gauge' % metric_item['metric']
            metric_item['value'] = line_data['value']
            data.append(metric_item)

        except Exception, e:
            # Catch them all!
            # print 'Parse error: %s' % e
            pass

    return data

