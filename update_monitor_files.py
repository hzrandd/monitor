#!/usr/bin/env python

'''
Created on 2014-04-01
Updated on 2014-04-01

'''


import hashlib
import httplib
import json
import os
import random
import time


SLEEPSECRANGE = 60
HTTPTIMEOUT = 3
UPDATEFILES = ['/etc/vm_monitor/send_monitor_data.py',
               '/etc/vm_monitor/monitor_settings.xml',
               '/etc/vm_monitor/update_monitor_files.py',
               '/etc/cron.d/inject_cron_job',
]


def wait_a_moment():
    global SLEEPSECRANGE
    # sleep a random seconds to avoid concurrent files updating
    sleep_time = random.randrange(SLEEPSECRANGE)
    time.sleep(sleep_time)


def send_request(uri):
    global HTTPTIMEOUT
    url = '169.254.169.254'
    method = 'GET'
    headers = {'Content-type': 'application/json',
               'Accept': 'application/json'}
    conn = httplib.HTTPConnection(url, timeout=HTTPTIMEOUT)
    conn.request(method, uri, '', headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()

    if response.status != 200:
        raise Exception()

    return json.loads(data)


def get_new_md5():
    uri = '/monitor-files-md5'
    new_md5_dict = send_request(uri)

    return new_md5_dict


def get_curr_md5():
    global UPDATEFILES
    curr_md5_dict = {}
    for file in UPDATEFILES:
        fname = os.path.basename(file)
        if not os.path.exists(file):
            curr_md5_dict[fname] = {'md5': None, 'full_path': file}
            continue

        with open(file) as f:
            fcontent = f.read()
        curr_md5_dict[fname] = {'md5': hashlib.md5(fcontent).hexdigest(),
                                'full_path': file}

    return curr_md5_dict


def update_monitor_file(full_path):
    fname = os.path.basename(full_path)
    uri = '/monitor-file-content/%s' % fname
    data = send_request(uri)

    file_content = data.get(fname)
    if not file_content:
        raise Exception()

    with open(full_path, 'w') as f:
        f.write(file_content)


def update_monitor_files(new_md5_dict, curr_md5_dict):
    for fname, fmd5 in new_md5_dict.iteritems():
        curr_finfo = curr_md5_dict.get(fname)
        # update file if it is not exists in vm or is not latest
        # NOTE: we should update the `update file` itself firstly,
        #                then we can know the path of new file by UPDATEFILES,
        #                this means a new file will be updated after two days
        if curr_finfo is None or curr_finfo['md5'] == fmd5:
            # this means we get a new file doesn't exist in UPDATEFILES, we
            # should wait for the `update file` itself being updated,
            # or this is a latest file needn't to update
            continue
        else:
            update_monitor_file(curr_finfo['full_path'])


if __name__ == '__main__':
    wait_a_moment()

    new_md5_dict = get_new_md5()
    if not new_md5_dict:
        raise Exception()

    curr_md5_dict = get_curr_md5()
    if not curr_md5_dict:
        raise Exception()

    update_monitor_files(new_md5_dict, curr_md5_dict)
