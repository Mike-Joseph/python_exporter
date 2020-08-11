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
import traceback


def Parse(text, command_data):
    """Parse the output of our command and prepare for export as list of dicts."""
    data = []

    '''
    (integer) 0
    '''

    # print 'redis_key: Parse Input: %s' % text

    # Split on \n or \r, either could happen in expect, because except is weird
    orig_lines = text.split('\n')
    lines = []
    for line in orig_lines:
        if '\r' in line:
            for new_line in line.split('\r'):
                lines.append(new_line)
        else:
            lines.append(line)


    found_auth = False
    is_data = False
    
    command = None

    for line in lines:
        item = {}

        try:
            # Get a dictionary of data from this line
            line_data = {}

            # Skip all the lines until we get our expected '+OK'
            if not found_auth and '+OK' not in line:
                continue
            # Skip this line, but set our Auth to good
            elif found_auth == False:
                found_auth = True
                continue

            # Skip empty lines
            if not line.strip():
                continue

            print 'Line Data: %s (%s=%s): %s' % (line_data, command, is_data, line)


            # If this is a command scrape (it alternates)
            if is_data == False:
                command = line.strip().replace(' ', '_')
                is_data = True

            else:
                # Create the labelset from our defaults
                item['labelset'] = {}
                for key, value in command_data['labelset'].items():
                    item['labelset'][key] = value

                # Take everything after the first character ":"
                value = line[1:]

                # Make a deep copy for each item, so we can add unique metrics from our common labelset -- Repeat for each metric
                metric = '%s_%s' % (command_data['metric_prefix'], command)
                metric_item = copy.deepcopy(item)
                metric_item['metric'] = metric
                metric_item['help'] = metric
                metric_item['type'] = '%s gauge' % metric
                metric_item['value'] = value.strip()

                print 'Added metric item: %s' % metric_item

                data.append(metric_item)

                # Cleare the command data
                is_data = False
                command = None  



        except Exception, e:
            # Catch them all!
            traceback.print_exc()
            pass

    return data

