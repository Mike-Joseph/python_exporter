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
import os
import os.path
import re
import json

import pprint

"""
TODO(geoff): How to collect docker stats:  /proc/PID#/cgroup:

root@sfo01-mr01:/etc/nginx# cat /proc/22571/cgroup
12:freezer:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
11:devices:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
10:perf_event:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
9:cpu,cpuacct:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
8:blkio:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
7:pids:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
6:rdma:/
5:cpuset:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
4:hugetlb:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
3:net_cls,net_prio:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
2:memory:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
1:name=systemd:/docker/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7
0::/system.slice/docker.service

cat /var/lib/docker/containers/c034e577c0d6505e6c05a42ba9cbe5fd9b5dd7eca9bb1a11c6fd1c020f398be7/config.v2.json

{"Name"} key is the docker container name.  Cache this.

TODO(geoff):  Need pid_ndex, which is normally 0, but if there are multiple of a process, it will have 1+, so we can not scale up metrics with every PID, but can track multiple 
        processes running, and keep them generally consistent.  Just use PID_Index as the lowest PID number first.

"""

# LOG_DEFAULT = logging.INFO
LOG_DEFAULT = logging.DEBUG

# Lock, so we only try to update our cache once
CACHE_LOCK = threading.Lock()

# This is the singleton label for the collection thread to be referenced
COLLECTION_THREAD = None

# Time to sleep until we collect again, so that we do not penalize the system
COLLECTION_INTERVAL_SLEEP = 2

# Because PSUTIL seems to be capable of using 100% CPU in production machines, we add a sleep every poll
PSUTIL_ITERATION_SLEEP = 1.0

# Psutil CPU Internal test
CPU_INTERVAL_TIME = 1.0

# Ignore these processes, they arent useful and use up our CPU
IGNORE_PROCESS_REGEX_LIST = ['scsi_.*']

# If their PPID is kthreadd, ignore them.  This should be static.
IGNORE_PPID_LIST = [2]

# Docker Container variables
DOCKER_CGROUP_PATH = '/proc/%(pid)d/cgroup'
DOCKER_CONFIG = '/var/lib/docker/containers/%(uuid)s/config.v2.json'      # Docker UUID from the Cgroup which gives us the Container Name

# Cache the Docker information.  The cache key is 'PID.PROCESSNAME', which will give a good collsion for the same process with the same process name.
DOCKER_CACHE = {}
DOCKER_CACHE_KEY = '%(pid)s.%(name)s'
DOCKER_CACHE_TIMEOUT = 60*30 # 30 minutes
DOCKER_CACHE_NEXT_TIME = time.time() + DOCKER_CACHE_TIMEOUT

# Docker commands
# DOCKER_COMMAND_NETSTAT = "docker exec %(name)s bash -c '/bin/netstat -ant | wc -l' "
DOCKER_COMMAND_NETSTAT = "docker exec %(name)s sh -c '/bin/netstat -ant | wc -l' "

# Process /proc/ netstat info.  Lots of information
PROCESS_PROC_NETSTAT_PATH = '/proc/%(pid)d/net/netstat'

# Per-process netstat exports.  There are categories, all of these will be lower cases to become metric names, ex: "node_process_netstat_tcpext_tcptimeouts"
PROCESS_PROC_NETSTAT_EXPORTS = {
    'TcpExt': ['TCPTimeouts', 'TCPMemoryPressures', 'TCPMemoryPressuresChrono', 'TCPKeepAlive', 'TCPSlowStartRetrans', 'TCPFastRetrans', 'TCPTimeouts', 'TCPRetransFail'],
    'IpExt': ['InOctets', 'OutOctets'],
}


def Log(text, level=LOG_DEFAULT):
    """Simple logging stub"""
    if level >= LOG_DEFAULT:
        print text


def EnsureDockerCacheClear():
    global DOCKER_CACHE, DOCKER_CACHE_NEXT_TIME

    # If it's time to clear the cache, clear it and set the next reset time
    if time.time() > DOCKER_CACHE_NEXT_TIME:
        DOCKER_CACHE = {}
        DOCKER_CACHE_NEXT_TIME = time.time() + DOCKER_CACHE_TIMEOUT


def GetNetstatInfo(process_info):
    """Returns a dict of information.  2 layers of dict.  Top keys:  'TcpExt' and 'IpExt', with another string/int dict beneath that. 

    NOTE(g): This function is hard coded to parse the /proc/PID/net/netstat format on Ubuntu, and may need more cases to work on different OSes.  Add those later.
    """
    netstat_path = PROCESS_PROC_NETSTAT_PATH % process_info

    data = {}

    with open(netstat_path) as fp:
        netstat = fp.read()

        for line in netstat.split('\n'):
            if ':' in line:
                top_header = line.split(':', 1)[0]
                # If this is the header line, we havent seen it before
                if top_header not in data:
                    data[top_header] = {}
                    all_headers = line.split(': ', 1)[1].split(' ')
                else:
                    all_values = line.split(': ', 1)[1].split(' ')

                    for count in range(0, len(all_headers)):
                        data[top_header][all_headers[count]] = all_values[count]

    return data


def GetDockerInfo(process_info):
    global DOCKER_CACHE

    # Ensure we clear the docker cache periodically, so it's up to date, in case something changes or we wrap PID numbers
    EnsureDockerCacheClear()

    # Docker data
    docker_info = {}

    # Create the cache key.  There is a chance for collision, but it requires flipping the PID space, and having the same process name.  We will add a timer to re-cache too
    docker_cache_key = DOCKER_CACHE_KEY % process_info

    # If we have this cached, return it
    if docker_cache_key in DOCKER_CACHE:
        return DOCKER_CACHE[docker_cache_key]

    # Get the CGroup information
    docker_cgroup_path = DOCKER_CGROUP_PATH % process_info

    # Get the Docker UUID
    if os.path.isfile(docker_cgroup_path):
        with open(docker_cgroup_path) as fp:
            cgroup_info = fp.read()
            for line in cgroup_info.split('\n'):
                # Docker Method
                if '/docker/' in line:
                    docker_info['uuid'] = line.split('/docker/', 1)[1]
                    # Done with this file
                    break
                # AWS ECS method
                elif '/ecs/' in line:
                    docker_info['uuid'] = line.split('/ecs/', 1)[1].split('/')[1]
                    # Done with this file
                    break

    # If we are a docker container, we have a UUID.  This is why we need to cache, because JSON decoding is slow and CPU intensive (when looped)
    if 'uuid' in docker_info:
        config_path = DOCKER_CONFIG % docker_info

        if os.path.isfile(config_path):
            with open(config_path) as fp:
                docker_config = fp.read()
                docker_config_data = json.loads(docker_config)

                # Strip off the leading `/`, as thats useful
                docker_info['name'] = docker_config_data['Name'][1:]

    # Store this information in the cache
    DOCKER_CACHE[DOCKER_CACHE_KEY] = docker_info
    
    return docker_info


def UpdateProcessContainer(process_info):
    """Accepts the dictionary of process information, sets variables in the process_info for containers.  Empty strings or zero values if they are not containers."""

    # Make another call so we can cache this data
    docker_info = GetDockerInfo(process_info)

    # If we have a docker container
    if 'name' in docker_info:
        # Get the container name
        process_info['container'] = docker_info['name']

        # Get the network connections
        netstat_cmd = DOCKER_COMMAND_NETSTAT % docker_info
        output = subprocess.Popen(netstat_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
        try:
            process_info['netstat_ant'] = int(output.strip())
        except ValueError, e:
            process_info['netstat_ant'] = -1            

        #TOOD(g): Anything else we want?
        pass


def GetMetricsFromProcess(process):
    """Returns a list of dicts for our metrics"""
    metrics = []

    # Create the labelset
    labelset = {
        'processname': process['name'],
        'index': process['process_index'],
        'user': process['username']
    }

    # If this is a container, so the values
    if 'container' in process:
        labelset['container'] = process['container']

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
    # metrics.append({'metric': 'memory_shared', 'value': process['memory_shared'], 'labelset': labelset})  # Doesnt work with AWS machines.  Seeing if commenting it will fix it

    # netstat -ant result
    if 'netstat_ant' in process:
        metrics.append({'metric': 'netstat_ant', 'value': process['netstat_ant'], 'labelset': labelset})

    # /proc/PID/net/netstat results
    if 'netstat' in process:
        for category, category_items in PROCESS_PROC_NETSTAT_EXPORTS.items():
            for key in category_items:
                metric_name = ('node_process_netstat_%s_%s' % (category, key)).lower()

                metrics.append({'metric': metric_name, 'value': process['netstat'][category][key], 'labelset': labelset})

    return metrics


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

    parent['memory_rss'] += child['memory_rss']
    parent['memory_vms'] += child['memory_vms']

    # If we have these values, accumulate
    if 'netstat_ant' in child:
        parent['netstat_ant'] += child['netstat_ant']


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


def IsProcessToIgnore(process):
    """Ignore some processes.  They arent worth collecting on and waste our resources."""
    for ignore_ppid in IGNORE_PPID_LIST:
        if process['ppid'] == ignore_ppid:
            return True

    for ignore_regex in IGNORE_PROCESS_REGEX_LIST:
        match = re.findall(ignore_regex, process['name'])
        if match:
            return True

    return False


def PrepareProcess(process):
    info = {}

    try:
        info['pid'] = process.pid
        info['ppid'] = process.ppid()

        info['name'] = process.name()

        # Detect if we should ignore this process
        if IsProcessToIgnore(info):
            return None

        # Sleep so we never consume much CPU.  I dont care if it's slow, it's better than nothing or burning CPU
        time.sleep(PSUTIL_ITERATION_SLEEP)

        # Get the rest of the data, after our sleep, since we arent ignoring this process
        info['cmdline'] = process.cmdline()
        info['username'] = process.username()
        info['num_threads'] = process.num_threads()
        info['memory_percent'] = process.memory_percent()

        # If we have an executable, track it
        if info['cmdline']:
            info['executable'] = info['cmdline'][0]

        # Deal with special process names
        if info['name'] == 'python' and info['cmdline'] and len(info['cmdline']) > 1:
            info['name_original'] = info['name']
            info['name'] = os.path.basename(info['cmdline'][1])

        elif info['name'] == 'python3' and info['cmdline'] and len(info['cmdline']) > 1:
            info['name_original'] = info['name']
            info['name'] = os.path.basename(info['cmdline'][1])

        elif info['name'] == 'java' and info['cmdline'] and len(info['cmdline']) > 1:
            info['name_original'] = info['name']
            info['name'] = os.path.basename(info['cmdline'][-1])

        # Log('PrepareProcess: %s' % info)

        # CPU
        cpu_percent = process.cpu_percent(interval=CPU_INTERVAL_TIME)
        if cpu_percent != None:
            info['cpu_percent'] = cpu_percent 
        else:
            info['cpu_percent'] = 0.0

        # Num FDs
        num_fds = process.num_fds()
        if cpu_percent != None:
            info['num_fds'] = num_fds        
        else:
            info['num_fds'] = 0.0

        # Open Files
        open_files = process.open_files()
        if open_files:
            info['open_files'] = open_files
        else:
            info['open_files'] = []


        # Create keys from special non-changeable data
        cpu_times = process.cpu_times()
        info['cpu_times_system'] = cpu_times.system
        info['cpu_times_user'] = cpu_times.user

        num_ctx_switches = process.num_ctx_switches()
        info['num_ctx_switches_voluntary'] = num_ctx_switches.voluntary

        memory_info = process.memory_info()
        info['memory_rss'] = memory_info.rss
        info['memory_vms'] = memory_info.vms
        # info['memory_shared'] = memory_info.shared  # Doesnt work with AWS machines.  Seeing if commenting it will fix it

        # Add information about the container, if it exists
        UpdateProcessContainer(info)

        #TODO(geoff): It turns out this is NOT netstat per process, but global netstat that is for some reason listed per process.  Not useful.  Leaving for now so we can repurpose to something we do want.
        # # Get the Netstat info, per process
        # netstat_info = GetNetstatInfo(info)
        # info['netstat'] = netstat_info

        # #DEBUG
        # print 'PID %(pid)s: Netstat: %(netstat)s' % info

        return info

    except psutil.NoSuchProcess:
        return None


def GetParentProcessItems():
    """Returns only the Parent Process data, having collected all the Child data into them as necessary.  Dict of dicts, keyed on PID"""
    # Get all processes by PIDs
    process_pids = {}
    for process in psutil.process_iter():
        # Ensure sane values and save into our PID dict
        info = PrepareProcess(process)
        if info:
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
    processes = []
    # Ensure they are in ascending order, so that our process_index value is fairly consistent (only changing with new process roll-over or PID death)
    keys = process_pids.keys()
    keys.sort()
    for key in keys:
        processes.append(process_pids[key])

    # Get the PID index.  We dont want to send PIDs to metric, because it grows the metric numbers too much, but we need to collect on each PID that is running.
    #       Because we track metrics by process name, any duplicate process names will wipe out each others metrics, as the labelset collides on PID name.
    #       So I will store an index, starting at 0 for each Process (lowest PID), so that we are semi-consistent, but do not grow metrics by having tons of unique
    #       labelsets.
    pid_indexes = {}        # Key is process name.  Value is int, starts at 0 and goes up each Process name match
    for process in processes:
        # Get current index
        index = pid_indexes.get(process['name'], 0)
        # Assign index
        process['process_index'] = index
        # Increment
        pid_indexes[process['name']] = index + 1

    return processes


def GetUsers():
    """Returns a dict of dicts, for each of our users logged in now, keyed on user name"""
    users = {}

    for user in psutil.users():
        if user.name not in users:
            users[user.name] = {'name': user.name, 'sessions': 0, 'last_login': 0, 'last_active':0}

        # Increment the logins
        users[user.name]['sessions'] += 1

        # Get the last time this user was active from their terminal dev
        dev_path = '/dev/%s' % user.terminal
        dev_last_active = os.stat(dev_path).st_atime
        if dev_last_active > users[user.name]['last_active']:
            users[user.name]['last_active'] = dev_last_active

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
    metrics.append({'metric': 'user_last_active', 'value': user['last_active'], 'labelset': labelset})

    return metrics


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


class CollectInfoThread(threading.Thread):

    def __init__(self):
        super(CollectInfoThread, self).__init__()

        # This is the cache we always return.  We update it by assignment when we run again
        self.cached_data = []

        Log('Created CollectInfoThread', logging.DEBUG)

        self.is_running = False
        self.is_quitting = False
        self.is_started = False


    def run(self):
        global COLLECTION_THREAD

        self.is_running = True

        Log('Running CollectInfoThread', logging.DEBUG)

        # Loop until we are signalled to quit
        while not self.is_quitting:
            try:
                # Get our Process data from Top
                self.cached_data = CollectProcesses_NoCache()

            except Exception, e:
                Log('CollectInfoThread Exception Failure: %s' % e)
                traceback.print_exc()

            # If we are forced to quit
            if GetQuitting():
                Log('Forced quit CollectInfoThread')
                break

            # Give back to the system, and loop waiting for quit or command
            time.sleep(COLLECTION_INTERVAL_SLEEP)

        Log('Closing CollectInfoThread', logging.DEBUG)
        self.is_running = False
        self.is_quitting = True

        COLLECTION_THREAD = None


def CollectProcesses():
    """Gets whatever is in the CollectionThread, and returns it, so we never block."""
    global COLLECTION_THREAD

    # Create the collection thread if it doesnt exist
    if COLLECTION_THREAD == None:
        # Make sure we only do this once
        with CACHE_LOCK:
            # Make sure it wasnt created before we got the lock so there isnt a race
            if COLLECTION_THREAD == None:
                COLLECTION_THREAD = CollectInfoThread()
                COLLECTION_THREAD.start()

    # Return whatever the cached data is
    return COLLECTION_THREAD.cached_data


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

