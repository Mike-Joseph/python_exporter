#!/usr/bin/env python

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

"""
Export shell and Python functions into Prometheus.
"""

import sys
import os
import yaml
import imp
import subprocess
import operator
import signal
import getopt

from multiprocessing import Process

from flask import *

# Stop logging all the request messages
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


# Globals
CONFIG_DATA = None

# Cache for importing Python modules.  So we dont always re-import them
MODULE_CACHE = {}

# Listening for Flask
LISTEN_PORT = None
LISTEN_ON = None

# When we are quitting, this is true
CONTROL_QUITTING = False


def GetQuitting():
    """Are we quitting?  Loaded modules can check."""
    global CONTROL_QUITTING

    return CONTROL_QUITTING


def ProcessYamls(config_data):
    """Process all the YAML data, starting Exporters as needed."""
    exporter_port = {}

    for path, data in config_data.items():
        # print 'ProcessYamls: %s (%s)' % (path, data['port'])

        export_list = []

        for command_data in data['commands']:
            export_data = ExecuteCommand(command_data)

            # Append to list in place
            export_list += export_data

        exporter_port[data['port']] = export_list

    output = ''

    for port, export_port_data in exporter_port.items():
        # print 'Port: %s' % port
        output += ExporterFormat(export_port_data)
        # print output

    return output


def ExporterFormat(export_port_data):
    output = ''

    # Sort the items by metric name, so we group them nicely
    export_port_data.sort(key=operator.itemgetter('metric'))

    # Print out the HELP/TYPE only once per metric
    help_cache = {}

    for item in export_port_data:
        if item['metric'] not in help_cache:
            help_cache[item['metric']] = True

            if 'help' in item:
                output += '# HELP %s\n' % item['help']
            if 'type' in item:
                output += '# TYPE %s\n' % item['type']

        # Metric - Labelset - Value
        output += '%s%s %s\n' % (item['metric'], FormatLabelset(item['labelset']), item['value'])

    return output


def FormatLabelset(labelset):
    output_list = []
    keys = labelset.keys()
    keys.sort()
    for key in keys:
        key_pair = '%s="%s"' % (key, labelset[key])
        output_list.append(key_pair)

    output = '{%s}' % ','.join(output_list)

    return output


def ExecuteCommand(command_data):
    """Execute one of our YAML commands, and parse it for exporter data"""
    # If we are executing a Shell Command, handle that
    if 'shell' in command_data:
        if 'shell_vars' in command_data and len(command_data['shell_vars']) > 0:
            shell = command_data['shell'] % command_data['shell_vars']
        else:
            shell = command_data['shell']

        # print 'Execute: %s' % shell

        output = subprocess.Popen(shell, shell=True, stdout=subprocess.PIPE).stdout.read()

    # Else, we are not executing a Shell Command, so output=None
    else:
        output = None

    # print 'Output: %s' % output

    command_module = LoadModule(command_data['module'])

    export_data = command_module.Parse(output, command_data)

    # print 'Export Data: %s' % export_data

    return export_data


def LoadModule(path):
    """Load the pluggable module.
    
    TODO(geoff): Cache these so we dont have to do it every request.
    """
    global MODULE_CACHE

    if path in MODULE_CACHE:
        return MODULE_CACHE[path]

    print 'Load Module: %s' % path

    module = imp.load_source(path, path)

    module.GetQuitting = GetQuitting

    print 'Load Module: Result: %s' % module

    MODULE_CACHE[path] = module

    return module


def Usage(error=None):
    if error:
        status = 1
        print '\nERROR: %s' % error
    else:
        status = 0

    print '\nusage: %s <yaml> <optional yaml>...' % os.path.basename(sys.argv[0])

    sys.exit(status)


def RunFlask(port, listen_on='0.0.0.0'):
    """Run the Flask server.  Implement all functions as sub-functions so we can set the port dynamically"""
    if listen_on == None:
        listen_on = '0.0.0.0'

    print 'Starting Flask: %s (%s)' % (port, listen_on)
    app = Flask(__name__)

    # app.add_url_rule('/', endpoint='index', view_func=RedirectToMetric)
    # app.add_url_rule('/metric', endpoint='metric', view_func=Metric)
    app.add_url_rule('/', endpoint='RedirectToMetric', view_func=RedirectToMetric)
    app.add_url_rule('/metrics', endpoint='Metric', view_func=Metric)

    app.run(host=listen_on, port=port, threaded=True)


def RedirectToMetric():
    return redirect('/metrics')


def Metric():
    try:
        output = ProcessYamls(CONFIG_DATA)
        response = Response(output, mimetype='text/plain')

    except Exception, e:
        print 'Metric Exception: %s' % e

    return response



def QuittingHandler(signum, frame):
    global CONTROL_QUITTING

    print 'Quit Signal: %s' % signum

    CONTROL_QUITTING = True

    # Sleep a little, and then exit
    # time.sleep(0)     # No need to delay, leaving so this can be used as a template/pattern

    raise RuntimeError('Quitting')


def IgnoreHandler(signum, frame):
    print 'Ignore Signal: %s' % signum


def Go():
    """Run in our own process, launching off of Main()"""
    global LISTEN_PORT, LISTEN_ON

    # Run the Flask server
    RunFlask(LISTEN_PORT, LISTEN_ON)


def Usage(error=None):
    if error:
        exit_code = 1

        print 'Error: %s\n' % error
    else:
        exit_code = 0

    print 'Usage: %s <options>' % os.path.basename(sys.argv[0])
    print ''
    print '  -h --help           Help'
    print '  --daemon            Use python multiprocessing to daemonize'
    print

    sys.exit(exit_code)


def Main(args=None):
    global CONFIG_DATA
    global LISTEN_PORT, LISTEN_ON


    port = None

    if not args:
        args = []


    (options, args) = getopt.getopt(args, 'h', ['help', 'daemon'])

    if len(args) < 1:
        Usage("Need at least 1 argument.  0 given.")


    # Run as a daemon with Python Multiprocessing.  Not useful under systemd, we lose the logs
    run_as_daemon = False

    for option, value in options:
        if option in ('-h', '--help'):
            Usage()
        elif option in ('--daemon'):
            run_as_daemon = True


    config_data = {}

    # Change the working directory based on the executable, so we can use relative paths for modules
    cwd = os.path.dirname(sys.argv[0])
    os.chdir(cwd)
    print 'Working Directory: %s' % cwd

    # print 'Data Directory: %s' % os.path.abspath(os.path.dirname(sys.argv[0]))
    # print 'User Directory: %s' % os.path.abspath(os.path.expanduser("~"))

    # Listen on IP
    listen_on = None

    for arg in args:
        if not os.path.isfile(arg):
            Usage('%s is not a valid file')

        with open(arg, "r") as stream:
            try:
                content = yaml.load(stream)
            except Exception, e:
                Usage("Failed to load YAML file: %s :: %s" % (arg, e))

            if port == None:
                port = int(content['port'])

            config_data[arg] = content

            # If we specify a listening port, take the first one
            if 'listen_on' in content and listen_on == None:
                listen_on = content['listen_on']


    if len(args) > 1:
        print 'All exporter results will return on the same port.  Multi-port not-yet implemented.'

    # Send this to our global, because of the Flask disconnect...
    CONFIG_DATA = config_data

    # Set Flask info
    LISTEN_ON = listen_on
    LISTEN_PORT = port

    # Handle the program quitting, so we can gracefully close our threads
    signal.signal(signal.SIGTERM, QuittingHandler)  # Kill -15
    signal.signal(signal.SIGINT, QuittingHandler)   # Keyboard Interrupt
    signal.signal(signal.SIGHUP, IgnoreHandler)     # Terminal Hangup, keep on going


    # If we arent running as a daemon, just run.  This is better under systemd
    if not run_as_daemon:
        Go()

    # Else, run as a daeomn with Python Multiprocessing
    else:
        # Initialize everything
        p = Process(target=Go)
        p.start()

        # When the above function completes, we will terminate it
        p.terminate()

        # Exit without error
        sys.exit(0)


if __name__ == '__main__':
    Main(sys.argv[1:])


