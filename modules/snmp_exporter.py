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
import yaml

import pprint

# LOG_DEFAULT = logging.INFO
LOG_DEFAULT = logging.DEBUG

# Lock, so we only try to update our cache once
CACHE_LOCK = threading.Lock()

# This is the singleton label for the collection thread to be referenced
COLLECTION_THREAD = None

# Time to sleep until we collect again, so that we do not penalize the system
COLLECTION_INTERVAL_SLEEP = 5

# Process /proc/ netstat info.  Lots of information
SNMP_WALK_COMMAND = '/usr/bin/snmpbulkwalk -t 5 -v2c -c %(password)s %(host)s %(oid)s'

# Per-process netstat exports.  There are categories, all of these will be lower cases to become metric names, ex: "node_process_netstat_tcpext_tcptimeouts"
SNMP_WALK_PATHS = {
    'juniper': {
        'path': 'data/snmp/juniper.yaml',
        'cache': None,  # Cache the YAML data here
    },
    'ts_digi': {
        'path': 'data/snmp/ts_digi.yaml',
        'cache': None,  # Cache the YAML data here
    },
    'pdu_tripp_lite_3phase': {
        'path': 'data/snmp/pdu_tripp_lite_3phase.yaml',
        'cache': None,  # Cache the YAML data here
    },
}

# Top level entries will be paths inside this path.  Change this as needed.
GIT_HOST_PATH = '/srv/git/data'

# This file combines what file to look in (top key) in data/ip/,
HOST_YAML = 'data/snmp/hosts.yaml'

# Configuration for all our keys and search, per config
CONFIG_YAML = 'data/snmp/config.yaml'
CONFIG_INFO = None

# Caching so we dont have to re-parse hosts all the time
CACHE_HOSTS = None

# Global dict for all the host oid data collection, so they are all running in long running threads
COLLECT_HOST_OID_DATA_THREADS = {}


def Log(text, level=LOG_DEFAULT):
    """Simple logging stub"""
    if level >= LOG_DEFAULT:
        print text


def LoadYaml(path):
    print 'Load YAML: %s' % path

    if os.path.isfile(path):
        with open(path) as fp:
            data = yaml.load(fp)
            return data

    return None


def LoadJson(path):
    print 'Load JSON: %s' % path

    if os.path.isfile(path):
        with open(path) as fp:
            data = json.load(fp)
            return data

    return None


def RunCommand(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = process.stdout.read()
    status = process.wait()

    return (status, output)


def CollectSingleSnmpOid(host, password, oid):
    args = {'host': host, 'password': password, 'oid': oid}
    cmd = SNMP_WALK_COMMAND % args

    # print cmd

    return RunCommand(cmd)


def GetMetricsFromSnmpResult_Single(labelset, interfaces, oid_data_all, oid_name, metric_type):
    metrics = []

    # Get our specific oid data
    oid_data = oid_data_all[oid_name]

    '''
    {'data_type': 'INTEGER',
    'oid': '1.3.6.1.2.1.2.2.1.8.508',
    'value': '1'},
    '''

    # Loop over the OID Data items
    for oid_item in oid_data:
        int_id = oid_item['oid'].split('.')[-1]

        #TODO(geoff): Put Interface Description data here 
        int_labelset = dict(labelset)
        int_labelset['interface'] = interfaces[int_id]

        # Update the labelset, if there are configed labels
        if 'label' in oid_item:
            int_labelset.update(oid_item['label'])

        metrics.append({'metric': oid_name, 'value': oid_item['value'], 'labelset': int_labelset})

    # print 'GetMetricsFromSnmpResult_Single: %s: %s' % (oid_name, len(metrics))

    return metrics



def GetMetricsFromSnmpResult(info):
    """Returns a list of dicts for our metrics"""
    global CONFIG_INFO

    metrics = []

    # print 'GetMetricsFromSnmpResult'
    # pprint.pprint(info)

    # Create the labelset
    host_labelset = {
        'instance': info['host']['data']['hostname'],
        'host': '-'.join(info['host']['data']['hostname'].split('.')[0].split('-')[:2]),
        'env': info['host']['data']['environment'],
        'dc': '%(location)s%(popId)s' % info['host']['data'],
    }

    info_config = CONFIG_INFO[info['host']['config']['config']]

    # Add Interface configs
    if 'interface' in info_config:
        interface_config = info_config['interface']

        if interface_config['key'] not in info['oids']:
            print 'Interface key not found yet, skipping: %s' % interface_config['key']
            return metrics

        # Loop over all our interfaces to gather stats.  May interface name (value) to last dotted number of the OID (interface ID) (key)
        interfaces = {}
        for interface in info['oids'][interface_config['key']]:
            # Key is int_id.  Value is interface name
            interfaces[interface['oid'].split('.')[-1]] = interface['value']


        # Counters
        for key in interface_config['counter_metrics']:
            metrics += GetMetricsFromSnmpResult_Single(host_labelset, interfaces, info['oids'], key, 'counter')

        # Gauges
        for key in interface_config['gauge_metrics']:
            metrics += GetMetricsFromSnmpResult_Single(host_labelset, interfaces, info['oids'], key, 'gauge')

        # Previous ways
        # metrics += GetMetricsFromSnmpResult_Single(host_labelset, interfaces, info['oids'], 'ifOperStatus')
        # metrics += GetMetricsFromSnmpResult_Single(host_labelset, interfaces, info['oids'], 'ifHCInOctets')
        # metrics += GetMetricsFromSnmpResult_Single(host_labelset, interfaces, info['oids'], 'ifHCOutOctets')

    # Add specific metrics
    if 'system' in info_config:
        system_config = info_config['system']

        # Gauge items
        for item in system_config['gauge_metrics']:
            metrics.append({'metric': item['key'], 'value': ProcessInfoValue(item, info), 'labelset': host_labelset, 'type': 'gauge'})

        # Counter items
        for item in system_config['gauge_metrics']:
            metrics.append({'metric': item['key'], 'value': ProcessInfoValue(item, info), 'labelset': host_labelset, 'type': 'counter'})

    return metrics


def ProcessInfoValue(process_info, info):
    """Do generalized processing for the value of this item"""
    item = process_info

    # Get the data
    value = info['oids'][item['key']]

    # Process the data, so we can do things like this to it, dynamically
    # metrics.append({'metric': 'sysUpTime', 'value': info['oids']['sysUpTime'][0]['value'][1:-1], 'labelset': host_labelset, 'type': 'gauge'})

    # If we have an index, take it
    if 'index' in item:
        value = value[item['index']]['value']

    # If we have an slice, cut the value up
    if 'slice' in item:
        if 'start' in item['slice'] and 'stop' in item['slice']:
            value = value[item['slice']['start']:item['slice']['stop']]
        elif 'start' in item['slice']:
            value = value[item['slice']['start']:]
        elif 'stop' in item['slice']:
            value = value[:item['slice']['stop']]

    return value


def GetHosts():
    """Get all the hosts, from cache, or load on first attempt"""
    global CACHE_HOSTS
    
    # If we dont have a cache
    if CACHE_HOSTS == None:
        # Cache all the SNMP Walk path data
        for (key, snmp_data) in SNMP_WALK_PATHS.items():
            SNMP_WALK_PATHS[key]['cache'] = LoadYaml(snmp_data['path'])

        # We will populate and return this, so it's cached
        CACHE_HOSTS = []

        host_match_data = LoadYaml(HOST_YAML)

        for (host_path_json, host_match_items) in host_match_data.items():
            host_path_data = LoadJson('%s/%s' % (GIT_HOST_PATH, host_path_json))

            # Match hosts and add them with the config
            for match_item in host_match_items:
                # Loop over all our hosts, and then we will use the item to match against entries
                for host_data in host_path_data:
                    is_match = True

                    # Look for any failed match conditions, to disqualify this match
                    for (match_key, match_value) in match_item['condition'].items():
                        if match_key not in host_data:
                            is_match = False
                            break
                        if match_key in host_data and host_data[match_key] != match_value:
                            is_match = False
                            break

                    # If we were a match, create the data and add to the CACHE_HOSTS
                    if is_match:
                        host_result = {
                            'data': host_data,
                            'config': match_item,
                        }

                        CACHE_HOSTS.append(host_result)


    return CACHE_HOSTS


def GetHostSnmpItems(host_data):
    """Get everything we need to extract metrics for this Host.  host_data is dict with keys 'config' and 'data'."""
    ''' {'config': {'condition': {'environment': 'net',
                           'type': 'fw',
                           'type_label': 'mgmt'},
             'config': 'juniper',
             'password': 'xxx'},
        'data': {u'cidr': u'198.19.100.0/24',
           u'environment': u'network',
           u'hostname': u'firewall.example.com',
           u'type': 'fw',
           u'interface_label': 'mgmt',
           u'ipAddress': u'198.19.100.1'}},
    '''
    global COLLECT_HOST_OID_DATA_THREADS

    info = {'host': host_data, 'oids': {}}

    # print SNMP_WALK_PATHS[host_data['config']['config']]

    snmp_oids = SNMP_WALK_PATHS[host_data['config']['config']]['cache']

    for (oid_name, oid_data) in snmp_oids.items():
        host_oid_key = '%s_%s' % (host_data['data']['ipAddress'], oid_data['oid'])

        # Ensure we have the thread set up for each of these
        if host_oid_key not in COLLECT_HOST_OID_DATA_THREADS:
            COLLECT_HOST_OID_DATA_THREADS[host_oid_key] = CollectHostOidDataThread(host_data, oid_data)
            COLLECT_HOST_OID_DATA_THREADS[host_oid_key].start()

        # oid_result = CollectSingleSnmpOid(host_data['data']['ipAddress'], host_data['config']['password'], oid_data['oid'])

        # Get whatever the current result is.  It will collect on the interval, as specified in oid_data
        oid_result = COLLECT_HOST_OID_DATA_THREADS[host_oid_key].result

        # Parse and store if we have data.  We wont on the first run as it's still collecting
        if oid_result != None:
            # print 'Result: %s: %s' % (oid_result[0], oid_result[1])
            info['oids'][oid_name] = ParseOidResult(oid_data, oid_result)

    return info


class CollectHostOidDataThread(threading.Thread):
    def __init__(self, host_data, oid_data):
        super(CollectHostOidDataThread, self).__init__()

        self.host_data = host_data
        self.oid_data = oid_data

        self.sleep_duration = COLLECTION_INTERVAL_SLEEP
        if 'interval' in self.oid_data:
            self.sleep_duration = self.oid_data['interval']

        self.finished = None

        self.result = None

    def run(self):
        global COLLECTION_THREAD

        while not COLLECTION_THREAD.is_quitting:
            # Collect it again
            self.result = CollectSingleSnmpOid(self.host_data['data']['ipAddress'], self.host_data['config']['password'], self.oid_data['oid'])

            # Wait for our period (not removing time it duration of execution)
            time.sleep(self.sleep_duration)

        self.finished = time.time()


def ParseOidResult(oid_data, oid_result):
    status = oid_result[0]
    output = oid_result[1]

    oid_values = []

    # If we failed, return empty
    if status != 0:
        return oid_values

    '''
    iso.3.6.1.2.1.31.1.1.1.10.565 = Counter64: 0
    iso.3.6.1.2.1.31.1.1.1.10.574 = Counter64: 0
    iso.3.6.1.2.1.31.1.1.1.10.576 = Counter64: 0
    '''

    for line in output.strip().split('\n'):
        parts = line.split(' ')

        oid_value = {}

        oid_value['oid'] = parts[0].replace('iso', '1')
        oid_value['data_type'] = parts[2].split(':')[0]
        oid_value['value'] = ' '.join(parts[3:]).replace('"', '').replace(')', '')

        # If we have parsing instructions, use them to fix the data
        if 'parse' in oid_data:
            if 'split' in oid_data['parse']:
                value = oid_value['value'].split(oid_data['parse']['split'])
                oid_value['value'] = value[oid_data['parse']['index']]


        # print 'OID Data: %s' % oid_data

        # Convert the value into a float from an integer
        if 'float' in oid_data:
            oid_value['value'] = float(oid_value['value']) * oid_data['float']

        # Update the labelset, if there are configed labels
        if 'label' in oid_data:
            oid_value['label'] = oid_data['label']


        oid_values.append(oid_value)

    return oid_values


def CollectSnmp_NoCache():
    """Collect raw data here, which can be formatted in Parse().  Called from Parse()"""
    metrics = []

    # print 'Collect SNMP: No cache: Start'

    # Determine which hosts we need to poll
    for host_data in GetHosts():

        # Get our rolled-up parent processes for creating metrics
        info = GetHostSnmpItems(host_data)

        # print 'Collect SNMP: No cache: SNMP Items: %s' % len(metrics)
        metrics += GetMetricsFromSnmpResult(info)

    # print 'Collect SNMP: No cache: Finish: %s' % len(metrics)

    return metrics


class CollectInfoThread(threading.Thread):

    def __init__(self, command_data):
        super(CollectInfoThread, self).__init__()

        # This is the cache we always return.  We update it by assignment when we run again
        self.cached_data = []
        self.cached_metric_output = []

        self.command_data = command_data

        Log('Created CollectInfoThread: SNMP', logging.DEBUG)

        self.is_running = False
        self.is_quitting = False
        self.is_started = False


    def run(self):
        global COLLECTION_THREAD

        self.is_running = True

        Log('Running CollectInfoThread: SNMP', logging.DEBUG)

        # Loop until we are signalled to quit
        while not self.is_quitting:
            try:
                # Get our Process data from Top
                self.cached_data = CollectSnmp_NoCache()

                self.cached_metric_output = ParseMetrics(self.command_data, self.cached_data)

                # print 'Running CollectInfoThread: SNMP: Cached output: %s' % len(self.cached_metric_output)

            except Exception, e:
                Log('CollectInfoThread: SNMP: Exception Failure: %s' % e)
                traceback.print_exc()

            # If we are forced to quit
            if GetQuitting():
                Log('Forced quit CollectInfoThread: SNMP')
                break

            # Give back to the system, and loop waiting for quit or command
            time.sleep(COLLECTION_INTERVAL_SLEEP)

        Log('Closing CollectInfoThread: SNMP', logging.DEBUG)
        self.is_running = False
        self.is_quitting = True

        COLLECTION_THREAD = None


def ParseMetrics(command_data, metrics):
    data = []

    for item in metrics:
        try:
            # Get a dictionary of data from this line
            line_data = {}

            # print 'SNMP Exporter: Initial Item: %s' % item

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
            print 'Exception: SNMP Exporter: %s' % e
            traceback.print_exc()
            pass

    return data


def CollectSnmp(command_data):
    """Gets whatever is in the CollectionThread, and returns it, so we never block."""
    global COLLECTION_THREAD
    global CACHE_LOCK
    global CONFIG_INFO

    # Create the collection thread if it doesnt exist
    if COLLECTION_THREAD == None:
        # Make sure we only do this once
        print 'Locking'
        with CACHE_LOCK:
            # Make sure it wasnt created before we got the lock so there isnt a race
            if COLLECTION_THREAD == None:
                # Load the Config Info
                CONFIG_INFO = LoadYaml(CONFIG_YAML)

                # Create the Collection Thread (only 1 here, not the worker pool)
                COLLECTION_THREAD = CollectInfoThread(command_data)
                COLLECTION_THREAD.start()

    # print 'Collect SNMP'

    # Return whatever the cached data is
    return COLLECTION_THREAD.cached_metric_output


def Parse(text, command_data):
    """Parse the output of our command and prepare for export as list of dicts."""
    # The data we will operate on, because we are not executing Shell Commands
    data = CollectSnmp(command_data)

    # print 'SNMP Exporter: Returned from Parse: %s' % len(data)

    return data

