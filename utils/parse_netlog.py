# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

import sys
import json

if len(sys.argv) < 2:
    exit(1)

with open(sys.argv[1], 'r') as file:
    data = json.load(file)

EVENT_TYPE_HTTP2_SESSION             = data['constants']['logEventTypes']['HTTP2_SESSION']
EVENT_TYPE_HTTP2_SESSION_CLOSE       = data['constants']['logEventTypes']['HTTP2_SESSION_CLOSE']
EVENT_TYPE_HTTP2_SESSION_RECV_GOAWAY = data['constants']['logEventTypes']['HTTP2_SESSION_RECV_GOAWAY']
SOURCE_TYPE_HTTP2_SESSION            = data['constants']['logSourceType']['HTTP2_SESSION']

PHASE_BEGIN = data['constants']['logEventPhase']['PHASE_BEGIN']

id_map = {}
host_map = {}

for event in data['events']:
    _id = event['source']['id']

    if event['type'] == EVENT_TYPE_HTTP2_SESSION and event['phase'] == PHASE_BEGIN:
        id_map[_id] = {
            'host': event['params']['host'],
            'prev_time': 0,
            'done': False
        }

    if _id not in id_map or id_map[_id]['done']:
        continue

    if event['type'] == EVENT_TYPE_HTTP2_SESSION_CLOSE:
        id_map[_id]['done'] = True
        idle_timeout = int(event['time']) - id_map[_id]['prev_time']
        host = id_map[_id]['host'].split(':')[0]

        if host in host_map:
            host_map[host] = max(idle_timeout, host_map[host])
        else:
            host_map[host] = idle_timeout
    elif event['type'] != EVENT_TYPE_HTTP2_SESSION_RECV_GOAWAY:
        id_map[_id]['prev_time'] = int(event['time'])

with open('idle_timeouts.json', 'w') as f:
    json.dump(host_map, f, indent=4, sort_keys=True)
