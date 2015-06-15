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

import configparser
import io
import os
import re
import tempfile
import subprocess

import requests
import zmq

working_dir = os.path.dirname(os.path.realpath(__file__))

config = configparser.ConfigParser()
config_file = os.path.join(working_dir, 'plaguescanner.conf')
config.read(config_file)

port = int(config['PlagueScanner']['Port'])

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind('tcp://*:{}'.format(port))

def get_scanner_results(sample):
    scanner_output = scan_file(sample)
    results = parse_output(scanner_output)
    return results

def scan_file(sample):
    sample_data = sample.read()
    with tempfile.NamedTemporaryFile(delete=True) as fp:
        fp.write(sample_data)
        scanner = subprocess.Popen(['/opt/eset/esets/sbin/esets_scan', '--clean-mode=none', '--no-quarantine', fp.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = scanner.communicate()
        output = stdout.splitlines()
        fp.close()
    return output

def parse_output(output):
    response = {'engine': 'ESET'}
    pest_name = re.search(b'threat=\"(.+?)\"', output[13])
    if pest_name:
        response['pest_name'] = pest_name.group(1).decode(encoding='utf-8')
    else:
        response['pest_name'] = None
    engine_version = re.match(b'ESET Command-line scanner, version (.+?),', output[1])
    if engine_version:
        response['engine_version'] = engine_version.group(1).decode(encoding='utf-8')
    return response

while True:
    message = socket.recv_string()
    print('Received request: {}'.format(message))
    message_parts = re.match('SCAN:(.+):(.+)', message)
    file = message_parts.group(2)
    response = requests.get('http://{}/{}'.format(config['PlagueScanner']['IP'], file))
    sample = io.BytesIO(response.content)
    reply = get_scanner_results(sample)
    socket.send_json(reply)
