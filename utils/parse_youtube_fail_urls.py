# Copyright (c) Microsoft Corporation.
# Licensed under the BSD-3-Clause license.

import sys
import re
from urllib.parse import urlparse, urlunparse, parse_qs

url_set = set()

def process_log_line(line):
    match_servehttp  = re.search(r'ServeHTTP\((.*?)\)', line)
    match_querymatch = re.search(r'NON-EXACT QUERY MATCH; resp query = (.*?)\)', line)

    if not (match_servehttp and match_querymatch):
        return

    url_replay = urlparse(match_servehttp.group(1))

    if not ('.googlevideo.com' in url_replay.netloc or '/videoplayback' in url_replay.path):
        return

    query_replay = parse_qs(url_replay.query)
    query_record = parse_qs(match_querymatch.group(1))

    if 'range' not in query_replay:
        return

    if 'range' not in query_record:
        return

    if query_replay['range'][0] != query_record['range'][0]:
        url_set.add(urlunparse(url_replay))

if __name__ == '__main__':
    with open(sys.argv[1], 'r') as f:
        for line in f:
            process_log_line(line)

    with open(sys.argv[2], 'w') as f:
        for url in url_set:
            f.write(f'{url}\n')
