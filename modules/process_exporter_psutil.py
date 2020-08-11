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
import time
import psutil
import threading
import subprocess

import pprint


# Cached data
CACHE_RESULT = None
CACHE_TIME = 0

# Seconds until the cache will refresh
CACHE_TIMEOUT = 19.5

# Lock, so we only try to update our cache once
CACHE_LOCK = threading.Lock()

# Top command, to get processes info in very CPU efficient way
TOP_COMMAND = 'top -b -c -d 7'
TOP_PROCESS = None

def GetMetricsFromProcess(process):
    """Returns a list of dicts for our metrics"""
    metrics = []

    # Create the labelset
    labelset = {
        'processname': process['name'],
        'user': process['username']
    }

    # pprint.pprint(process)

    metrics.append({'metric': 'cpu_percent', 'value': process['cpu_percent'], 'labelset': labelset})

    metrics.append({'metric': 'cpu_user', 'value': process['cpu_times_user'], 'labelset': labelset, 'type': 'counter'})
    metrics.append({'metric': 'cpu_system', 'value': process['cpu_times_system'], 'labelset': labelset, 'type': 'counter'})

    metrics.append({'metric': 'open_files', 'value': len(process['open_files']), 'labelset': labelset})
    metrics.append({'metric': 'fds', 'value': process['num_fds'], 'labelset': labelset})

    metrics.append({'metric': 'context_switch_voluntary', 'value': process['num_ctx_switches_voluntary'], 'labelset': labelset})

    metrics.append({'metric': 'threads', 'value': process['num_threads'], 'labelset': labelset})

    metrics.append({'metric': 'memory_percent', 'value': process['memory_percent'], 'labelset': labelset})

    metrics.append({'metric': 'memory_rss', 'value': process['memory_rss'], 'labelset': labelset})
    metrics.append({'metric': 'memory_vms', 'value': process['memory_vms'], 'labelset': labelset})
    metrics.append({'metric': 'memory_shared', 'value': process['memory_shared'], 'labelset': labelset})

    return metrics


def PrepareProcess(process):
    # These should be zero, not None
    zero_value_keys = ['cpu_percent', 'num_fds']

    for key in zero_value_keys:
        if key not in process:
            continue

        if process[key] == None:
            process[key] = 0.0

    # These should be empty lists, not None
    empty_list_keys = ['open_files']

    for key in empty_list_keys:
        if key not in process:
            continue

        if process[key] == None:
            process[key] = []

    # Create keys from special non-changeable data
    process['cpu_times_system'] = process['cpu_times'].system
    process['cpu_times_user'] = process['cpu_times'].user
    process['num_ctx_switches_voluntary'] = process['num_ctx_switches'].voluntary

    process['memory_rss'] = process['memory_info'].rss
    process['memory_vms'] = process['memory_info'].vms
    process['memory_shared'] = process['memory_info'].shared


def CombineParentProcessData(parent, child):
    """Combine a child processes values (aggregate) into a Parent process"""
    # print 'Combine: %s (%s) <- %s' % (parent['name'], parent['pid'], child['pid'])

    parent['cpu_percent'] += child['cpu_percent']
    parent['cpu_times_user'] += child['cpu_times_user']
    parent['cpu_times_system'] += child['cpu_times_system']

    parent['num_ctx_switches_voluntary'] += child['num_ctx_switches_voluntary']

    parent['num_threads'] += child['num_threads']
    parent['open_files'] += child['open_files']

    parent['num_fds'] += child['num_fds']

    parent['memory_percent'] += child['memory_percent']

    parent['memory_rss'] += child['memory_info'].rss
    parent['memory_vms'] += child['memory_info'].vms


def GetParentProcess(child_process, ppid, process_pids):
    """Looking for the ppid in the Process PIDs dict.  Recurses, until it finds the top one that isnt owned by a system PID (0,1)"""
    # If we didnt find the parent, return None
    if ppid not in process_pids:
        return None

    # Get the parent
    parent_process = process_pids[ppid]

    # If this process's parent is a different name, it's not the legimate child for tracking purposes
    if child_process['name'] != parent_process['name']:
        return None

    # If the PPID's parent is a system PID, then return the parent process, we are done.  This is a parent level process
    if parent_process['ppid'] in (0, 1):
        return parent_process

    # Else, we need to look further up for a higher parent
    else:
        # See if we can find a higher level parent
        higher_parent = GetParentProcess(child_process, parent_process['ppid'], process_pids)

        if higher_parent != None:
            return higher_parent
        else:
            return parent_process


def GetParentProcessItems():
    """Returns only the Parent Process data, having collected all the Child data into them as necessary.  Dict of dicts, keyed on PID"""
    # Get all processes by PIDs
    process_pids = {}
    for proc in psutil.process_iter():
        try:
            # info = proc.as_dict(attrs=['open_files', 'num_fds', 'username', 'pid', 'ppid', 'name', 'cmdline', 'memory_percent', 'num_threads'])
            # info = proc.as_dict(attrs=['open_files', 'num_fds', 'username', 'pid', 'ppid', 'name', 'cmdline', 'memory_percent', 'num_ctx_switches', 'num_threads'])
            # info = proc.as_dict(attrs=['open_files', 'num_fds', 'username', 'pid', 'ppid', 'name', 'cmdline'])
            info = proc.as_dict()
        except psutil.NoSuchProcess:
            pass
        else:
            # Ensure sane values and save into our PID dict
            PrepareProcess(info)
            process_pids[info['pid']] = info

    # Get the keys, so we can remove them
    pids = process_pids.keys()
    pids.sort()

    remove_child_pids = []

    for pid in pids:
        process = process_pids[pid]

        # If this is a child of an existing process, group it, and it has the same name
        parent_process = GetParentProcess(process, process['ppid'], process_pids)
        if parent_process:
            CombineParentProcessData(parent_process, process)

            # Remove this later
            remove_child_pids.append(pid)

    # Clean up all the children
    for pid in remove_child_pids:
        del process_pids[pid]

    # Our list of Parent Processes, adding all our remaining process pids, that we didnt delete because they were children
    processes = process_pids.values()

    return processes


def GetUsers():
    """Returns a dict of dicts, for each of our users logged in now, keyed on user name"""
    users = {}

    for user in psutil.users():
        if user.name not in users:
            users[user.name] = {'name': user.name, 'sessions': 0, 'last_login': 0}

        # Increment the logins
        users[user.name]['sessions'] += 1

        # If this login is newer than previous ones, update to it.  So we know when they login again
        #TODO(geoff): It would be best to see when their TTY was last active, but takes more work than this.  Not sure how the `who` command does this now.  Keeping it simple first.
        if user.started > users[user.name]['last_login']:
            users[user.name]['last_login'] = user.started

    return users


def GetMetricsFromUsers(user):
    """For each user, produce a dict of metric data"""
    metrics = []

    labelset = {
        'user': user['name']
    }

    # Get last login from now
    metrics.append({'metric': 'user_session', 'value': user['sessions'], 'labelset': labelset})
    metrics.append({'metric': 'user_last_login', 'value': user['last_login'], 'labelset': labelset})

    return metrics


def GetProcessDataFromTop():
    """Returns a list of dicts for our processes from the top command"""
    global TOP_PROCESS

    # If we already have a Top Process, and it is dead, then clear it so we will restart
    if TOP_PROCESS != None and TOP_PROCESS.poll() != None:
        TOP_PROCESS = None


    if TOP_PROCESS == None:
        StartTopCommand()


def StartTopCommand():
    """Start our top command and let it run"""
    global TOP_PROCESS

    if TOP_PROCESS == None:
        TOP_PROCESS = subprocess.Popen(TOP_COMMAND)


def CollectProcesses_NoCache():
    """Collect raw data here, which can be formatted in Parse().  Called from Parse()"""
    metrics = []

    # Get our rolled-up parent processes for creating metrics
    for info in GetParentProcessItems():
        is_system_process = False

        if not info['cmdline']:
            is_system_process = True

        # If this is not a system process
        if not is_system_process:
            metrics += GetMetricsFromProcess(info)

    # Get our users and create metrics from them
    users = GetUsers()
    for user in users.values():
        metrics += GetMetricsFromUsers(user)


    return metrics


def CollectProcesses():
    """Caches the call from CollectProcess_NoCache()"""
    global CACHE_RESULT, CACHE_TIME, CACHE_TIMEOUT, CACHE_LOCK

    # If we need to update our CACHE_RESULT
    if time.time() > CACHE_TIME + CACHE_TIMEOUT:
        with CACHE_LOCK:
            # If we got the lock and we STILL need to update our cache result (wasnt done in a different thread)
            if time.time() > CACHE_TIME + CACHE_TIMEOUT:
                CACHE_RESULT = CollectProcesses_NoCache()
                CACHE_TIME = time.time()

    return CACHE_RESULT


def Parse(text, command_data):
    """Parse the output of our command and prepare for export as list of dicts."""
    data = []

    # The data we will operate on, because we are not executing Shell Commands
    processes = CollectProcesses()

    for item in processes:
        try:
            # Get a dictionary of data from this line
            line_data = {}

            # print 'Initial Item: %s' % item

            # Create the labelset from our defaults
            for key, value in command_data['labelset'].items():
                item['labelset'][key] = value

            # Make a deep copy for each item, so we can add unique metrics from our common labelset -- Repeat for each metric
            metric_item = copy.deepcopy(item)
            metric_item['metric'] = '%s_%s' % (command_data['metric_prefix'], item['metric'])
            metric_item['help'] = metric_item['metric']
            if 'type' not in item:
                metric_item['type'] = '%s gauge' % metric_item['metric']
            else:
                metric_item['type'] = '%s %s' % (metric_item['metric'], item['type'])

            # Add the value
            metric_item['value'] = str(item['value']).strip()

            # print 'Added metric item: %s' % metric_item

            data.append(metric_item)


        except Exception, e:
            # Catch them all!
            traceback.print_exc()
            pass

    return data

