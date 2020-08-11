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
import logging
import re
import glob
import shutil
import os
import sys

import pprint


# Cached data
CACHE_RESULT = None
CACHE_TIME = 0

# Seconds until the cache will refresh
CACHE_TIMEOUT = 19.5

# Lock, so we only try to update our cache once
CACHE_LOCK = threading.Lock()

# Top command, to get processes info in very CPU efficient way
TOP_COMMAND = '/usr/bin/top -b -d 7'

# Create the Top thread to manage reading the data in the background
TOP_THREAD = None
TOP_THREAD_LOCK = threading.Lock()

# LOG_DEFAULT = logging.INFO
LOG_DEFAULT = logging.DEBUG

# Seconds to sleep in the thread to give back to CPU before looping
THREAD_INTERVAL_SLEEP = 0.1

# These names will roll-up children even though the names are different.  Made for collecting massive children of kernel processes
SPECIAL_PARENT_NAMES = ['kthreadd', '[kthreadd]']


def Log(text, level=LOG_DEFAULT):
    """Simple logging stub"""
    if level >= LOG_DEFAULT:
        print text


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


class TopThread(threading.Thread):

    def __init__(self):
        super(TopThread, self).__init__()

        # List of dics, with all our process information, that we update
        self.process_list = []

        # This is what we use for metrics, so we role up same-named children with parent processes, because thats more interesting for metrics
        self.parent_process_list = []

        # This cannot be trusted, as it may be partially updated.  Moved into self.process_list when complete
        self.update_processes = []

        # We keep updating this to get our total read buffer
        #TODO(geoff): Convert to mutable strings
        self.read_buffer = ''

        self.process = None
        self.StartTopCommand()

        Log('Created TopThread', logging.DEBUG)

        self.is_running = False
        self.is_quitting = False
        self.is_started = False


    def _CombineParentProcessData(self, parent, child):
        """Combine a child processes values (aggregate) into a Parent process"""
        # Log('Combine: %s (%s) <- %s' % (parent['name'], parent['pid'], child['pid']))
        # # Log('Parent: %s' % (pprint.pformat(parent)))
        # # Log('Child: %s' % (pprint.pformat(child)))


        parent['cpu_percent'] += child['cpu_percent']

        parent['num_page_faults_major'] += child['num_page_faults_major']

        parent['num_threads'] += child['num_threads']

        parent['memory_percent'] += child['memory_percent']

        parent['memory_resident'] += child['memory_resident']
        parent['memory_virtual'] += child['memory_virtual']

        parent['num_fds'] += child['num_fds']
        
        parent['swap'] += child['swap']


    def _GetParentProcess(self, child_process, ppid, process_pids):
        """Looking for the ppid in the Process PIDs dict.  Recurses, until it finds the top one that isnt owned by a system PID (0,1)"""
        global SPECIAL_PARENT_NAMES

        # If we didnt find the parent, return None
        if ppid not in process_pids:
            return None

        # Get the parent
        parent_process = process_pids[ppid]

        # If this parent process is one of the special ones, then even though the name is different, we roll it up
        if parent_process['name'] in SPECIAL_PARENT_NAMES:
            # print 'Found Special Parent name: %s <- %s' % (parent_process['name'], child_process['name'])
            return parent_process

        # If this process's parent is a different name, it's not the legimate child for tracking purposes
        if child_process['name'] != parent_process['name']:
            return None

        # If the PPID's parent is a system PID, then return the parent process, we are done.  This is a parent level process
        if parent_process['ppid'] in (0, 1):
            return parent_process

        # Else, we need to look further up for a higher parent
        else:
            # See if we can find a higher level parent
            higher_parent = self._GetParentProcess(child_process, parent_process['ppid'], process_pids)

            if higher_parent != None:
                return higher_parent
            else:
                return parent_process


    def GetParentProcessItems(self):
        """Returns only the Parent Process data, having collected all the Child data into them as necessary.  Dict of dicts, keyed on PID"""
        # Get all processes by PIDs
        process_pids = {}
        for process in self.process_list:
                process_pids[process['pid']] = process

        # pprint.pprint(process_pids)

        # Get the keys, so we can remove them
        pids = process_pids.keys()
        pids.sort()

        remove_child_pids = []

        for pid in pids:
            process = process_pids[pid]

            # If this is a child of an existing process, group it, and it has the same name
            parent_process = self._GetParentProcess(process, process['ppid'], process_pids)
            if parent_process:
                self._CombineParentProcessData(parent_process, process)

                # Remove this later
                remove_child_pids.append(pid)

        # Clean up all the children
        for pid in remove_child_pids:
            del process_pids[pid]

        # Our list of Parent Processes, adding all our remaining process pids, that we didnt delete because they were children
        processes = process_pids.values()

        # pprint.pprint(processes)

        # Our list of parent processes
        return processes


    def _GetMetricsFromProcess(self, process):
        """Returns a list of dicts for our metrics"""
        metrics = []

        # Create the labelset
        labelset = {
            'processname': process['name'],
            'user': process['username']
        }

        # pprint.pprint(process)

        metrics.append({'metric': 'cpu_percent', 'value': process['cpu_percent'], 'labelset': labelset})

        metrics.append({'metric': 'page_faults', 'value': process['num_page_faults_major'], 'labelset': labelset})

        metrics.append({'metric': 'threads', 'value': process['num_threads'], 'labelset': labelset})

        metrics.append({'metric': 'memory_percent', 'value': process['memory_percent'], 'labelset': labelset})

        metrics.append({'metric': 'memory_rss', 'value': process['memory_resident'], 'labelset': labelset})
        metrics.append({'metric': 'memory_vms', 'value': process['memory_virtual'], 'labelset': labelset})
        metrics.append({'metric': 'memory_shared', 'value': process['memory_shared'], 'labelset': labelset})
        metrics.append({'metric': 'swap', 'value': process['swap'], 'labelset': labelset})

        metrics.append({'metric': 'fds', 'value': process['num_fds'], 'labelset': labelset})

        return metrics


    def GetMetrics(self):
        """Get the metrics for all our processes"""
        metrics = []

        # Get our Parent Process items, for a better way for exportingc
        self.parent_process_list = self.GetParentProcessItems()

        # Get metrics for each rolled-up parent process
        for process in self.parent_process_list:
            metrics += self._GetMetricsFromProcess(process)

        return metrics


    def StartTopCommand(self):
        """Start our top command and let it run"""
        global TOP_COMMAND

        if self.process == None:
            Log('Running Top Command: %s' % TOP_COMMAND)

            environment = os.environ.copy()
            
            Log('Environment: %s' % environment)

            self.process = subprocess.Popen(TOP_COMMAND, stdout=subprocess.PIPE, shell=True, env=environment)


    def GetProcessDataFromTop(self):
        """Returns a list of dicts for our processes from the top command"""
        # If we already have a Top Process, and it is dead, then clear it so we will restart
        if self.process != None and self.process.poll() != None:
            self.process = None

        # If we dont have a top process, start one
        if self.process == None:
            self.StartTopCommand()

        # Log('Processing data:')

        # Our lines we can process
        lines = []

        # Handle the stupid bufferent for subprocess, because it cant give me a readline() line-by-line...
        single_read_buffer = self.process.stdout.read(1024)
        # Log('Single Read Buffer: "%s"' % single_read_buffer)
        parts = single_read_buffer.split('\n')

        if len(parts) < 1:
            self.read_buffer += parts[0]
        else:
            line = self.read_buffer + parts[0]
            lines.append(line)

            for line in parts[1:-1]:
                lines.append(line)

            self.read_buffer = parts[-1]


        # Processs the lines we know on.  We will defer making a new set of processes until we see top run again, so always losing delay time between runs
        for line in lines:
            # Log('Processing line: %s' % line)

            # We are starting again, so stop processing, so we clear the last read of process list
            if 'top - ' in line:
                # Save our update_processes into our final process_list, and clear update_processes for new ingestion
                self.process_list = self.update_processes
                self.update_processes = []
                Log('Skipping: Breaking on new top run', logging.DEBUG)
                break

            # line = remove_whilespace_re.sub(line, ' ')
            line = re.sub(' +', ' ', line).strip()

            Log('Cleaned line: %s' % line, logging.DEBUG)

            cols = line.split(' ')

            # Skip anything less than our known values
            if len(cols) < 15:
                Log('Skipping: Less than 15 columns', logging.DEBUG)
                continue

            data = {}

            # Enforce this line is for a process
            try:
                data['pid'] = int(cols[0])
            except ValueError, e:
                Log('Skipping: Not a valid pid', logging.DEBUG)
                continue

            data['username'] = cols[1]
            data['priority'] = cols[2]
            data['nice'] = int(cols[3])
            data['memory_virtual'] = self._GetValueNumber(cols[4])
            data['memory_resident'] = self._GetValueNumber(cols[5])
            data['memory_shared'] = self._GetValueNumber(cols[6])
            data['status'] = cols[7]
            data['cpu_percent'] = float(cols[8])
            data['memory_percent'] = float(cols[9])
            data['cpu_time'] = cols[10]
            data['ppid'] = int(cols[11])
            data['num_threads'] = self._GetValueNumber(cols[12])
            data['swap'] = self._GetValueNumber(cols[13])
            data['num_page_faults_major'] = self._GetValueNumber(cols[14])
            data['name'] = cols[15]
            data['command'] = cols[15:]

            # Get all the file descriptors open, so we can track those too
            #NOTE(g): This only works if we are root, or they are our processes
            fd_paths = glob.glob('/proc/%s/fd/*' % data['pid'])
            data['num_fds'] = len(fd_paths)

            # Log('Found Data: %s' % pprint.pformat(data), logging.DEBUG)

            # Append the process
            self.update_processes.append(data)


    def _GetValueNumber(self, value):
        try:
            return int(value)
        except ValueError, e:
            int_value = value[:-1]
            scale = value[-1]

            value = float(int_value)
            if scale == 'k':
                return value * 1024
            if scale == 'm':
                return value * 1024 * 1024
            if scale == 'g':
                return value * 1024 * 1024 * 1024

            return value


    def run(self):
        self.is_running = True

        Log('Running TopThread', logging.DEBUG)

        # Loop until we are signalled to quit
        while not self.is_quitting:
            try:
                # Get our Process data from Top
                self.GetProcessDataFromTop()

            except Exception, e:
                Log('TopThread Exception Failure: %s' % e)
                traceback.print_exc()

            # If we are forced to quit
            if GetQuitting():
                Log('Forced quit TopThread')
                break

            # Give back to the system, and loop waiting for quit or command
            time.sleep(THREAD_INTERVAL_SLEEP)

        Log('Closing TopThread', logging.DEBUG)
        self.is_running = False
        self.is_quitting = True


def CollectProcesses_NoCache():
    """Collect raw data here, which can be formatted in Parse().  Called from Parse()"""
    metrics = []

    # Get our process data from Top.  It sucks to parse this, but top is very efficient (0.3% CPU, and other methods seem to be eggregious)
    # processes = GetProcessDataFromTop()

    if TOP_THREAD != None:
        metrics += TOP_THREAD.GetMetrics()


    # # Get our users and create metrics from them
    # users = GetUsers()
    # for user in users.values():
    #     metrics += GetMetricsFromUsers(user)


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
    global TOP_THREAD

    data = []

    # Create and Run the Top Thread to continually read from Top results, which should use ~0.3% CPU, instead of everyone else who seems to use a lot of CPU
    if TOP_THREAD == None:
        exe_path = os.path.abspath(os.path.dirname(sys.argv[0]))
        user_path = os.path.abspath(os.path.expanduser("~"))
        # print 'Data Directory: %s/data/' % exe_path
        # print 'User Directory: %s' % user_path

        # Copy the toprc to the user location, because we need it for top's output to be correct
        print 'Copying .toprc: %s -> %s' % ('%s/data/toprc' % exe_path, '%s/.toprc' % user_path)
        shutil.copyfile('%s/data/toprc' % exe_path, '%s/.toprc' % user_path)
        try:
            # Try to copy to root's toprc too, since SUID may mess this up
            shutil.copyfile('%s/data/toprc' % exe_path, '/root/.toprc')
        except:
            print 'Cant copy to /root/.toprc'
            pass


        TOP_THREAD = TopThread()
        TOP_THREAD.start()

    # The data we will operate on, because we are not executing Shell Commands
    processes = CollectProcesses_NoCache()

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

