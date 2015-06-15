#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2014, 2015 Robert Simmons
#
# This file is part of PlagueScanner.
#
# PlagueScanner is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Foobar is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import configparser
import json
import os
import queue
import tempfile
import threading

import zmq

parser = argparse.ArgumentParser(description='Scan a file.')
parser.add_argument('sample', metavar='SAMPLE', type=str, help='File name of the file that you wish to scan.')
args = parser.parse_args()

working_dir = os.path.dirname(os.path.realpath(__file__))

config = configparser.ConfigParser()
config_file = os.path.join(working_dir, 'plaguescanner.conf')
config.read(config_file)

scanners = {}
for scanner in config.sections():
    if scanner != 'PlagueScanner':
        scanners[scanner] = config[scanner]['IP']

port = int(config['PlagueScanner']['Port'])
q = queue.Queue()

results = []
def worker():
    while True:
        scanner, ip, filename = q.get()
        results.append(send_to_scanner(scanner, ip, filename))
        q.task_done()

def send_to_scanner(scanner, ip, filename):
    message = 'SCAN:{}:{}'.format(scanner, filename)
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect('tcp://{}:{}'.format(ip, port))
    socket.send_string(message)
    reply = socket.recv_json()
    return reply

for num_threads in scanners:
    t = threading.Thread(target=worker)
    t.daemon = True
    t.start()

if args.sample:
    fh = open(os.path.join(working_dir, args.sample), 'rb')
    sample_data = fh.read()
    fh.close()
    outbound_samples = config['PlagueScanner']['OutboundSamplesDir']
    with tempfile.NamedTemporaryFile(prefix='', dir=outbound_samples) as fp:
        fp.write(sample_data)
        os.chmod(fp.name, 0o644)
        filename = os.path.basename(fp.name)
        for scanner, ip in scanners.items():
            work = (scanner, ip, filename)
            q.put(work)
        q.join()
        fp.close()
    print(json.dumps(results, sort_keys=True, indent=4))
