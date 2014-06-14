#!/usr/bin/env python

'''
Created on 2012-07-23
Updated on 2014-02-21

'''

import hashlib
import hmac
import httplib
import json
import os
import time
import urllib
from xml.etree import ElementTree


PERIOD_TIME = 60
MONITOR_PATH = '/etc/vm_monitor/'
INFO_PATH = MONITOR_PATH + 'info'
TEMP_PATH = MONITOR_PATH + 'temp'
XML_PATH = MONITOR_PATH + 'monitor_settings.xml'
META_PATH = MONITOR_PATH + 'metadata'
TEMP_DATA = {
             'total_cpu_time': 0,
             'last_cpu_idle_time': 0,
             'disk_read_request': 0,
             'disk_write_request': 0,
             'disk_read': 0,
             'disk_write': 0,
             'disk_read_delay': 0,
             'disk_write_delay': 0,
             'network_receive_bytes': 0,
             'network_transfer_bytes': 0,
             'disk_partition_info': {},
             'timestamp': 0,
             'netcards_flow': {}
}

NET_CARD_LIST = ['eth0', 'eth1', 'eth2']
SERVICE_LIST = ['openstack', 'NVS', 'NQS']


def get_metadata_from_nova():
    '''
        Call nova api to get vm metadata.
    '''
    url = '169.254.169.254'
    httpMethod = 'GET'
    requestURI = '/openstack/latest/meta_data.json'
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    conn = httplib.HTTPConnection(url, timeout=3)
    conn.request(httpMethod, requestURI, '', headers)
    response = conn.getresponse()
    meta_data = response.read()
    conn.close()
    if response.status != 200:
        raise Exception()
    meta_data_dict = json.loads(meta_data)
    return meta_data_dict


def store_metadata(metadata):
    meta_file_write = open(META_PATH, 'w')
    try:
        jsona = json.dumps(metadata)
        meta_file_write.write(jsona)
    except Exception:
        # NOTE(hzrandd): when exception happens raise it, stop sending datas.
        raise
    finally:
        meta_file_write.close()


def get_metadata_cache():
    '''
        Get instance uuid of this virtual machine from metadata cache
    '''
    if os.path.exists(META_PATH):
        meta_file_read = open(META_PATH, 'r')
        metadata_cache = meta_file_read.read()
        meta_file_read.close()
        if metadata_cache:
            metadata = json.loads(metadata_cache)
            return metadata
        else:
            return {}
    else:
        return {}


def get_ori_user():
    '''
        Get project id of this virtual machine from metadata api firstly,
        if failed, get it from metadata cache
    '''
    try:
        metadata = get_metadata_from_nova()
        store_metadata(metadata)
        ori_user = metadata.get('project_id')
    except Exception:
        ori_user = get_metadata_cache().get('project_id')

    if ori_user is None:
        raise Exception()

    return ori_user


def get_uuid():
    '''
        Get uuid of this virtual machine, try to call metadata api firstly,
        if failed, get uuid from metadata cache
    '''
    # NOTE(hzrandd): should get metadata information from nova every time.
    try:
        metadata = get_metadata_from_nova()
        store_metadata(metadata)
        uuid = metadata.get('uuid')
    except Exception:
        uuid = get_metadata_cache().get('uuid')

    if uuid is None:
            raise Exception()

    return uuid


def read_info_file():
    '''
        Read config info from local file, default path: /etc/vm_monitor/info
    '''
    with open(INFO_PATH, 'r') as info_file:
        data_from_file = info_file.read()
    info_file_dict = json.loads(data_from_file)
    return info_file_dict


#
#    Use temp file to store last minute data.
#    default path: /etc/vm_monitor/temp
#
def check_temp_expired(temp_timestamp):
    period = long(time.time()) - temp_timestamp
    if period >= 0 and period <= PERIOD_TIME + 30:
        return False
    else:
        return True


def read_temp_file():
    '''
        When monitor start it will read temp file which has stored datas
        last 1 minute ago.
        When last timestamp is not in 1~90 seconds, it
        means temp file is expired. The data in temp file
        should be record again.
        @return: True/False
    '''
    try:
        global TEMP_DATA
        if os.path.exists(TEMP_PATH):
            temp_file_read = open(TEMP_PATH, 'r')
            tempdata = temp_file_read.read()
            temp_file_read.close()
            if tempdata:
                temp_data = json.loads(tempdata)
                is_expired = check_temp_expired(temp_data['timestamp'])
                if not is_expired:
                    for key in temp_data.keys():
                        if key in TEMP_DATA:
                            TEMP_DATA[key] = temp_data[key]
                    return True
        return False
    except Exception:
        # NOTE(hzrandd): when exception happens, return False
        return False


def write_temp_file():
    '''
        When monitor catch the newest datas, it will store them
        into temp file.
        It will record timestamp into temp file for mark the temp
        file is expired or not.
        @raise exception: Exception
    '''
    try:
        temp_file_write = open(TEMP_PATH, 'w')
        TEMP_DATA['timestamp'] = long(time.time())
        jsona = json.dumps(TEMP_DATA)
        temp_file_write.write(jsona)
    except Exception:
        # NOTE(hzrandd): when exception happens raise it, stop sending datas.
        raise
    finally:
        temp_file_write.close()


def get_interval_time():
    interval = long(time.time()) - TEMP_DATA['timestamp']
    if interval > 0:
        return interval
    else:
        return PERIOD_TIME


def handle_metadata(info_file_dict):
    service = info_file_dict.get('service')
    ori_user = info_file_dict.get('ori_user', '')
    aggregation_items = info_file_dict.get('aggregation_items')
    resource_type = info_file_dict.get('resource_type')
    if ori_user == '' and service == 'openstack':
        info_file_dict['ori_user'] = get_ori_user()
    if aggregation_items == None or aggregation_items == '':
        info_file_dict['aggregation_items'] = {}
    if service == 'openstack' and resource_type != 'openstack':
        info_file_dict['resource_type'] = 'openstack'
    return True


def notify_platform_partition_change(disk_partition_info):
    '''
        notify platform when partition changed only when service supports
        diskPartition metric.

        :param disk_partition_info: {'sys':['vda1'],
                                     'logic':['vda1', 'vdb1', 'dm-0']}
    '''
    try:
        info_file_dict = read_info_file()
        service = info_file_dict.get('service')
        resource_type = info_file_dict.get('resource_type')
        setting_root = ElementTree.parse(XML_PATH)
        setting_services = setting_root.findall('service')
        metric_types = []
        for s in setting_services:
            if (service == s.attrib.get('name') and
                    resource_type == s.attrib.get('resource_type')):
                metric_types = s.findall('metric')

        metrics = [m.attrib.get('name') for m in metric_types]
        if 'diskPartition' not in metrics:
            return False

        request_uri = '/rest/V1/nvs/updatePartitionInfo'
        system_partitions = ','.join(disk_partition_info['sys'])
        logic_partitions = ','.join(disk_partition_info['logic'])
        # partition dimension is like openstack=1.1.1.1 or RDS=123456
        parti_dimension = info_file_dict.get('service') + '=' + get_uuid()
        send_request = SendRequest(info_file_dict=info_file_dict,
                                   request_uri=request_uri,
                                   system_partitions=system_partitions,
                                   logic_partitions=logic_partitions,
                                   parti_dimension=parti_dimension)
        response = send_request.send_request_to_server()
        if response.status == 200:
            return True
        else:
            return False
    except Exception:
        return False


class GetSystemUsage(object):
    '''
        Get system resources usage include disk, network, cpu, memory.
        CPU: get cpu usage percent.
        Memory: get total memory(KB), free memory and used memory datas.
        Disk: get disk read/write data((KB)), requests and used delay(ms).
        Network: get network I/O datas(bytes) and vm ip.
    '''
    def _get_cpu_usage_dict(self):
        '''
            Get CPU usage(percent) by vmstat command.
            @return: {'cpu_usage': 0.0}
        '''
        cpu_path = '/proc/stat'
        if os.path.exists(cpu_path):
            cpu_file_read = open(cpu_path, 'r')
            cpu_read_line = cpu_file_read.readline()
            cpu_file_read.close()
            cpu_infos = cpu_read_line.split()[1:-1]
            total_cpu_time = 0L
            for cpu_info in cpu_infos:
                total_cpu_time += long(cpu_info)
            last_cpu_time = TEMP_DATA['total_cpu_time']
            cpu_idle_time = long(cpu_infos[3])
            last_cpu_idle_time = TEMP_DATA['last_cpu_idle_time']
            total_cpu_period = float(total_cpu_time - last_cpu_time)
            idle_cpu_period = float(cpu_idle_time - last_cpu_idle_time)

            if total_cpu_period <= 0 or idle_cpu_period < 0:
                cpu_usage = 0.0
            else:
                idle_usage = idle_cpu_period / total_cpu_period * 100
                cpu_usage = round(100 - idle_usage, 2)

            TEMP_DATA['total_cpu_time'] = total_cpu_time
            TEMP_DATA['last_cpu_idle_time'] = cpu_idle_time
        else:
            cpu_usage = 0.0
        return {'cpu_usage': cpu_usage}

    def _get_loadavg_dict(self):
        '''
            Get loadavg info from /proc/loadavg.
            @return: {'loadavg_5': 4.32}
        '''
        with open('/proc/loadavg', 'r') as loadavg_file_read:
            loadavg_info_line = loadavg_file_read.readline()
        loadavg_5 = float(loadavg_info_line.split()[1])

        return {'loadavg_5': loadavg_5}

    def _get_memory_usage_dict(self):
        '''
            Get memory info(MB) from /proc/meminfo.
            @return: {'total_memory': 1, 'free_memory': 1,
                      'used_memory': 1, 'memory_usage_rate': 45}
            free_memory = MemFree + Buffers + Cached
            used_memory = MemTotal - free_memory
            memory_usage_rate = used_memory * 100 / MemTotal
        '''
        with open('/proc/meminfo', 'r') as mem_file_read:
            mem_info_lines = mem_file_read.readlines()

        total_memory = long(mem_info_lines[0].split()[1]) / 1024
        free_memory = (long(mem_info_lines[1].split()[1])
                       + long(mem_info_lines[2].split()[1])
                       + long(mem_info_lines[3].split()[1])) / 1024
        used_memory = total_memory - free_memory
        memory_usage_rate = (used_memory * 100) / total_memory

        return {
            'total_memory': total_memory,
            'free_memory': free_memory,
            'used_memory': used_memory,
            'memory_usage_rate': memory_usage_rate
        }

    def _get_disk_data(self):
        '''
            Use command df to get all partitions` used/available disk
            datas(MB).
            Find string start with '/dev/' and split it with '/' to get
            disks` name into dict disks. Like '/dev/vda1' to get 'vda'.
            Call _get_disk_data_by_proc() to get datas from /proc/diskstats.
            @return: {
                      'disk_read_request': 0, 'disk_write_request': 0,
                      'disk_read': 0, 'disk_write': 0, 'disk_read_delay': 1,
                      'disk_write_delay': 1, 'used_disk': 0,
                      'avail_disk': 0,
                      'disk_partition_info': {'sys': ['vda1'],
                                              'logic': ['vdb1', 'dm-0']}
                      'disk_partition_data': {'vda': {'avail_capacity': 500,
                                                      'partition_usage': 15}}
                    }
        '''
        def _get_mounted_disks():
            '''
                Get mounted disks/partitions from /proc/mounts.
                @return: partition:target dict: {'vda1': '/', 'dm-0': '/mnt'}
            '''
            with open('/proc/mounts', 'r') as f:
                mounts = f.readlines()
            mounted_disks = {}
            for mount in mounts:
                if mount.startswith('/dev/'):
                    mount = mount.split()
                    partition = os.path.realpath(mount[0]).rsplit('/')[-1]
                    target = mount[1]
                    if (partition not in mounted_disks and
                                    target not in mounted_disks.values()
                                    or (target == '/' and
                                        '/' not in mounted_disks.values())):
                        mounted_disks[partition] = target
            return mounted_disks

        def _get_fs_info(path):
            """Get free/used/total space info for a filesystem

            :param path: Any dirent on the filesystem
            :returns: A dict containing:
                     :free: How much space is free (in bytes)
                     :used: How much space is used (in bytes)
                     :total: How big the filesystem is (in bytes)
            """
            hddinfo = os.statvfs(path)
            total = hddinfo.f_frsize * hddinfo.f_blocks
            free = hddinfo.f_frsize * hddinfo.f_bavail
            used = hddinfo.f_frsize * (hddinfo.f_blocks - hddinfo.f_bfree)
            return {'total': float(total) / 1024 / 1024,
                    'free': float(free) / 1024 / 1024,
                    'used': float(used) / 1024 / 1024}

        def _get_patition_info(disks, total_disk_info):
            partitions = {'sys': [], 'logic': []}
            for partition, target in disks.iteritems():
                fs_info = _get_fs_info(target)
                free = fs_info['free']
                used = fs_info['used']
                total = fs_info['total']
                usage = round(used / total * 100, 2)
                total_disk_info['disk_partition_data'][partition] = {
                                        'avail_capacity': free,
                                        'partition_usage': usage
                                    }
                total_disk_info['used_disk'] += used
                total_disk_info['avail_disk'] += free
                if target == '/':
                    partitions['sys'].append(partition)
                else:
                    partitions['logic'].append(partition)

            # NOTE(hzrandd): here to store all the partition names
            total_disk_info['disk_partition_info'] = partitions

        def _get_disk_data_by_proc(disks, total_disk_info):
            '''
                Get disks infos from /proc/diskstats, like:
                    read/write datas(KB),
                    request times(count time),
                    read/write paid time(ms) and so on.
                And set the datas into total_disk_info dict.
            '''
            partitions = disks.keys()
            with open('/proc/diskstats') as diskstats:
                disk_datas = diskstats.readlines()
            for disk_data in disk_datas:
                datas = disk_data.split()
                if datas[2] in partitions:
                    total_disk_info['disk_read_request'] += long(datas[3])
                    total_disk_info['disk_write_request'] += long(datas[7])
                    total_disk_info['disk_read'] += long(datas[5]) / 2
                    total_disk_info['disk_write'] += long(datas[9]) / 2
                    total_disk_info['disk_read_delay'] += long(datas[6])
                    total_disk_info['disk_write_delay'] += long(datas[10])

        disks = _get_mounted_disks()
        total_disk_info = {
            'disk_read_request': 0,
            'disk_write_request': 0,
            'disk_read': 0,
            'disk_write': 0,
            'disk_read_delay': 0,
            'disk_write_delay': 0,
            'used_disk': 0,
            'avail_disk': 0,
            'disk_partition_info': {},
            'disk_partition_data': {}
        }

        _get_patition_info(disks, total_disk_info)
        _get_disk_data_by_proc(disks, total_disk_info)
        return total_disk_info

    def _get_disk_usage_rate_dict(self):
        '''
            Assemble all the datas collected from _get_disk_data().
            @return: {
                      'disk_read_request': 0.0, 'disk_write_rate': 0.0,
                      'disk_write_delay': 0.0, 'disk_read_delay': 0.0,
                      'disk_read_rate': 0.0, 'used_disk': 0,
                      'disk_write_request': 0, 'disk_partition_info': ['vda1'],
                      'disk_partition_data': {'vda': {'avail_capacity': 500,
                                                      'partition_usage': 15}}
                     }
        '''
        global TEMP_DATA
        now_disk_data = self._get_disk_data()
        write_request_period_time = (now_disk_data['disk_write_request']
                                     - TEMP_DATA['disk_write_request'])
        read_request_period_time = (now_disk_data['disk_read_request']
                                    - TEMP_DATA['disk_read_request'])
        if write_request_period_time == 0:
            write_request_period_time = 1
        if read_request_period_time == 0:
            read_request_period_time = 1

        disk_write_rate = (float(now_disk_data['disk_write']
                                 - TEMP_DATA['disk_write'])
                                     / get_interval_time())
        disk_read_rate = (float(now_disk_data['disk_read']
                                - TEMP_DATA['disk_read'])
                                    / get_interval_time())
        disk_write_request = (float(now_disk_data['disk_write_request']
                                    - TEMP_DATA['disk_write_request'])
                                        / get_interval_time())
        disk_read_request = (float(now_disk_data['disk_read_request']
                                   - TEMP_DATA['disk_read_request'])
                                       / get_interval_time())
        disk_write_delay = (float(now_disk_data['disk_write_delay']
                                  - TEMP_DATA['disk_write_delay'])
                                      / float(write_request_period_time))
        disk_read_delay = (float(now_disk_data['disk_read_delay']
                                 - TEMP_DATA['disk_read_delay'])
                                     / float(read_request_period_time))
        if (disk_write_rate < 0 or disk_read_rate < 0
                or disk_write_request < 0 or disk_read_request < 0
                or disk_write_delay < 0 or disk_read_delay < 0):
            disk_write_rate = 0.0
            disk_read_rate = 0.0
            disk_write_request = 0.0
            disk_read_request = 0.0
            disk_write_delay = 0.0
            disk_read_delay = 0.0

        disk_usage_dict = {
                'used_disk': now_disk_data['used_disk'],
                'disk_write_rate': disk_write_rate,
                'disk_read_rate': disk_read_rate,
                'disk_write_request': disk_write_request,
                'disk_read_request': disk_read_request,
                'disk_write_delay': disk_write_delay,
                'disk_read_delay': disk_read_delay,
                'disk_partition_info': now_disk_data['disk_partition_info'],
                'disk_partition_data': now_disk_data['disk_partition_data']
        }

        # when partition info changed, notify platform with new partition info
        last_partition_info = {}
        is_success = True
        if (now_disk_data.get('disk_partition_info') !=
                TEMP_DATA.get('disk_partition_info')):
            is_success = notify_platform_partition_change(
                            now_disk_data.get('disk_partition_info', []))
            if not is_success:
                last_partition_info = TEMP_DATA['disk_partition_info']

        for key in now_disk_data.keys():
            if key in TEMP_DATA:
                TEMP_DATA[key] = now_disk_data[key]

        # FIXME(hzrandd): here add for don`t record partition info into temp.
        # To do this when partition monitor enable, partition change will occur
        if not is_success:
            TEMP_DATA['disk_partition_info'] = last_partition_info

        return disk_usage_dict

    def _get_network_flow_data(self):
        '''
            Get network flow datas(Byte) from network card by
            analysing the file /proc/net/dev.
            @return: {'total_receive_bytes': 369,
                      'total_transfer_bytes': 702,
                      'netcards_flow': [{'net': 'private',
                                         'receive_bytes': 123,
                                         'transfer_bytes': 234},
                                         {'net': 'idc',
                                         'receive_bytes': 123,
                                         'transfer_bytes': 234},
                                         {'net': 'public',
                                         'receive_bytes': 123,
                                         'transfer_bytes': 234}]
                    }
        '''
        total_receive_bytes = 0L
        total_transfer_bytes = 0L
        total_receive_packages = 0L
        total_transfer_packages = 0L
        netcards_flow = []

        with open('/proc/net/dev', 'r') as net_dev:
            network_lines = net_dev.readlines()
        for network_line in network_lines:
            network_datas = network_line.replace(':', ' ').split()
            try:
                if network_datas[0] in NET_CARD_LIST:
                    total_receive_bytes += long(network_datas[1])
                    total_receive_packages += long(network_datas[2])
                    total_transfer_bytes += long(network_datas[9])
                    total_transfer_packages += long(network_datas[10])

                    if network_datas[0] == 'eth0':
                        net_type = 'private'
                    elif network_datas[0] == 'eth1':
                        net_type = 'idc'
                    if network_datas[0] == 'eth2':
                        net_type = 'public'
                    net_flow = {'net': net_type,
                                'receive_bytes': long(network_datas[1]),
                                'transfer_bytes': long(network_datas[9])}
                    netcards_flow.append(net_flow)
            except Exception:
                continue

        return {'total_receive_bytes': total_receive_bytes,
                'total_transfer_bytes': total_transfer_bytes,
                'netcards_flow': netcards_flow}

    def _get_flow_rate_for_each_card(self, old_netcards_flow,
                                     now_netcards_flow,
                                     interval_time):
        '''
        Transfer now_netcards_flow data with old_netcards_flow_data into
        netcards_rate.

        @return: 'netcards_rate': [{'net': 'private',
                                    'receive_rate': 0.0,
                                    'transfer_rate': 0.0},
                                   {'net': 'idc',
                                    'receive_rate': 0.0,
                                    'transfer_rate': 0.0},
                                   {'net': 'public',
                                    'receive_rate': 0.0,
                                    'transfer_rate': 0.0}]
        '''
        old_ncs_flow_dict = {}
        for nc_flow in old_netcards_flow:
            old_ncs_flow_dict[nc_flow['net']] = {
                'receive_bytes': nc_flow['receive_bytes'],
                'transfer_bytes': nc_flow['transfer_bytes']}

        netcards_rate = []
        for nc_flow in now_netcards_flow:
            if nc_flow['net'] in old_ncs_flow_dict:
                net_flow = old_ncs_flow_dict[nc_flow['net']]
                old_receive_bytes = net_flow['receive_bytes']
                old_transfer_bytes = net_flow['transfer_bytes']
            else:
                old_receive_bytes = 0
                old_transfer_bytes = 0

            now_receive_bytes = nc_flow['receive_bytes']
            now_transfer_bytes = nc_flow['transfer_bytes']

            receive_rate = (float(now_receive_bytes - old_receive_bytes)
                                            / 1024 / interval_time)
            transfer_rate = (float(now_transfer_bytes - old_transfer_bytes)
                                            / 1024 / interval_time)
            if receive_rate < 0 or transfer_rate < 0:
                receive_rate = 0
                transfer_rate = 0

            nc_rate = {'net': nc_flow['net'],
                       'receive_rate': receive_rate,
                       'transfer_rate': transfer_rate}
            netcards_rate.append(nc_rate)

        return netcards_rate

    def _get_network_flow_rate_dict(self):
        '''
            Assemble dict datas collect from _get_network_flow_data()
            for network flow rate in 60s.
            Set network flow datas to TEMP_DATA.
            @return: {
                      'total_receive_rate': 0.0,
                      'total_transfer_rate': 0.0
                      'netcards_rate': [{'net': 'private',
                                         'receive_rate': 0.0,
                                         'transfer_rate': 0.0},
                                         {'net': 'idc',
                                         'receive_rate': 0.0,
                                         'transfer_rate': 0.0},
                                         {'net': 'public',
                                         'receive_rate': 0.0,
                                         'transfer_rate': 0.0}]
                    }
        '''
        old_receive_bytes = TEMP_DATA['network_receive_bytes']
        old_transfer_bytes = TEMP_DATA['network_transfer_bytes']
        old_netcards_flow = TEMP_DATA['netcards_flow']

        network_flow = self._get_network_flow_data()
        now_receive_bytes = network_flow['total_receive_bytes']
        now_transfer_bytes = network_flow['total_transfer_bytes']
        now_netcards_flow = network_flow['netcards_flow']

        interval_time = get_interval_time()
        receive_rate = (float(now_receive_bytes - old_receive_bytes)
                                            / 1024 / interval_time)
        transfer_rate = (float(now_transfer_bytes - old_transfer_bytes)
                                            / 1024 / interval_time)
        netcards_rate = self._get_flow_rate_for_each_card(old_netcards_flow,
                                                          now_netcards_flow,
                                                          interval_time)
        if receive_rate < 0 or transfer_rate < 0:
            receive_rate = 0
            transfer_rate = 0

        network_info_dict = {
                'total_receive_rate': receive_rate,
                'total_transfer_rate': transfer_rate,
                'netcards_rate': netcards_rate
        }
        TEMP_DATA['network_receive_bytes'] = now_receive_bytes
        TEMP_DATA['network_transfer_bytes'] = now_transfer_bytes
        TEMP_DATA['netcards_flow'] = now_netcards_flow
        return network_info_dict

    def get_system_usage_datas(self):
        '''
            Get all system datas and assemble them into all_system_usage_dict.
            The key names of all_system_usage_dict are the same as XML setting.
        '''
        cpu_usage = self._get_cpu_usage_dict()
        loadavg = self._get_loadavg_dict()
        memory_usage = self._get_memory_usage_dict()
        network_usage = self._get_network_flow_rate_dict()
        disk_usage = self._get_disk_usage_rate_dict()
        all_system_usage_dict = {
            'cpuUsage': cpu_usage['cpu_usage'],
            'memUsage': memory_usage['used_memory'],
            'networkReceive': network_usage['total_receive_rate'],
            'networkTransfer': network_usage['total_transfer_rate'],
            'netCardsFlowRate': network_usage['netcards_rate'],
            'diskUsage': disk_usage['used_disk'],
            'diskWriteRate': disk_usage['disk_write_rate'],
            'diskReadRate': disk_usage['disk_read_rate'],
            'diskWriteRequest': disk_usage['disk_write_request'],
            'diskReadRequest': disk_usage['disk_read_request'],
            'diskWriteDelay': disk_usage['disk_write_delay'],
            'diskReadDelay': disk_usage['disk_read_delay'],
            'diskPartition': [disk_usage['disk_partition_info'],
                              disk_usage['disk_partition_data']],
            'loadavg_5': loadavg['loadavg_5'],
            'memUsageRate': memory_usage['memory_usage_rate']
        }

        return all_system_usage_dict


class DataFormater(object):

    def _setting_params(self, metricName, dimensions,
                        aggregationDimensions, sum_value, unit):
        '''
            Setting the metric element parameters and datas.
            @return: dict
        '''
        metric_datas = {
            'metricName': metricName,
            'dimensions': dimensions,
            'aggregationDimensions': aggregationDimensions,
            'sum': sum_value,
            'maxinum': sum_value,
            'mininum': sum_value,
            'sampleCount': 1,
            'createTime': long(time.time() * 1000),
            'unit': unit
        }

        return metric_datas

    def _get_diskpartition_dimension_type_a(self, info_file_dict,
                                                   identify_id):
        dimension = info_file_dict['resource_type'] + '=' + identify_id
        return dimension

    def _get_diskpartition_dimension_type_b(self, identify_id,
                                            partition_identity,
                                            partition_name):
        dimension = ('partition=' + identify_id + '#::#' +
                partition_identity + '#::#' + partition_name)
        return dimension

    def _get_ddb_rds_diskpartition_dimension(self, partition_name,
                                             partition_identity,
                                             identify_id,
                                             info_file_dict):
        return self._get_diskpartition_dimension_type_a(info_file_dict,
                                                        identify_id)

    def _get_ddb_sqlpxyserver_diskpartition_dimension(self, partition_name,
                                                      partition_identity,
                                                      identify_id,
                                                      info_file_dict):
        return self._get_diskpartition_dimension_type_a(info_file_dict,
                                                        identify_id)

    def _get_ddb_master_diskpartition_dimension(self, partition_name,
                                                partition_identity,
                                                identify_id,
                                                info_file_dict):
        return self._get_diskpartition_dimension_type_a(info_file_dict,
                                                        identify_id)

    def _get_rds_rds_diskpartition_dimension(self, partition_name,
                                             partition_identity,
                                             identify_id,
                                             info_file_dict):
        return self._get_diskpartition_dimension_type_a(info_file_dict,
                                                        identify_id)

    def _get_openstack_openstack_diskpartition_dimension(self, partition_name,
                                                         partition_identity,
                                                         identify_id,
                                                         info_file_dict):
        return self._get_diskpartition_dimension_type_b(identify_id,
                                                     partition_identity,
                                                     partition_name)

    def _get_identify_id(self, info_file_dict):
        if info_file_dict['service'] in SERVICE_LIST:
            # for openstack resource_id is store VM ip (eth0)
            identify_id = get_uuid()
        else:
            identify_id = info_file_dict['resource_id']
        return identify_id

    def _get_aggregation_dimensions_for_metric(self, metric,
                                               info_file_dict):
        aggregation_items = info_file_dict['aggregation_items']

        aggregations = metric.getiterator('aggregation')
        aggregationDimensions = ''
        for aggregation in aggregations:
            ag_name = aggregation.attrib['name']
            if ag_name in aggregation_items:
                if aggregationDimensions != '':
                    aggregationDimensions += ','
                    aggregationDimensions += (ag_name + '=' +
                            aggregation_items[ag_name].encode('utf-8'))
        return aggregationDimensions

    def _get_netcards_flowrate_usage(self, metric_datas,
                                     netcards_flowrate,
                                     aggregationDimensions,
                                     identify_id):
        unit = "Kilobytes/Second"

        for nc_flowrate in netcards_flowrate:
            net_type = nc_flowrate['net']
            receive_rate = nc_flowrate['receive_rate']
            transfer_rate = nc_flowrate['transfer_rate']
            dimensions = 'netcard=' + identify_id + '#::#' + net_type

            metric_data = self._setting_params('networkReceive',
                                                dimensions,
                                                aggregationDimensions,
                                                receive_rate,
                                                unit)
            metric_datas['metricDatas'].append(metric_data)

            metric_data = self._setting_params('networkTransfer',
                                                dimensions,
                                                aggregationDimensions,
                                                transfer_rate,
                                                unit)
            metric_datas['metricDatas'].append(metric_data)

    def _get_partition_usage(self, metric_datas,
                                    info_file_dict, all_usage_dict,
                                    metric_type, monitor_partition,
                                    aggregationDimensions,
                                    identify_id,
                                    service):
        partition_info = all_usage_dict[metric_type][0]
        partition_datas = all_usage_dict[metric_type][1]
        partition_setting = {
            'avail_capacity': ['availCapacity', 'Megabytes'],
            'partition_usage': ['partitionUsage', 'Percent']
        }

        def _get_dimension(partition_name, partition_identity, service):
            name = service.attrib['name'].lower()
            re_type = service.attrib['resource_type'].lower()
            dimension_func = self.__getattribute__(
                '_get_%s_%s_diskpartition_dimension' % (name, re_type))
            dimension = dimension_func(partition_name, partition_identity,
                                       identify_id, info_file_dict)
            return dimension

        for partition_name in partition_datas:
            if partition_name in partition_info['sys']:
                partition_identity = 'system'
            elif partition_name in partition_info['logic']:
                partition_identity = 'logic'
            else:
                continue
            # NOTE(hzrandd): getting  monitor_partition from xml setting that
            # parse from the mertic of diskpartition.such as:
            # ['system', 'logic'] or ['system'] or ['logic']
            if partition_identity not in monitor_partition:
                continue
            dimension = _get_dimension(partition_name, partition_identity,
                                         service)
            for parti_data_name in partition_datas[partition_name]:
                parti_setting = partition_setting[parti_data_name]
                data = partition_datas[partition_name]
                parti_metric_name = parti_setting[0]
                parti_unit = parti_setting[1]
                parti_metric_data = data[parti_data_name]
                # FIXME(hzrandd): should keep partitionUsage unique
                # when statistic one more partition in the future, such as:
                # parti_metric_name + partition_name
                metric_data = self._setting_params(parti_metric_name,
                                                   dimension,
                                                   aggregationDimensions,
                                                   parti_metric_data,
                                                   parti_unit)
                metric_datas['metricDatas'].append(metric_data)

    def _get_monitor_partition_types(self, metric):
        # NOTE(hzrandd):get type name from the XML when the metric is
        # diskpartition,and return which partition should monitored.
        types = metric.getiterator('types')
        if not types:
            # NOTE(hzrandd): return [] when the service has not setted
            # diskpartition to monitor.
            return []
        partition_name = [name.attrib['name'] for name in types]
        return partition_name

    def _get_service_from_xml(self, info_file_dict):
        # Read XML settings and set aggregation dimension
        # infos and store metric datas
        root = ElementTree.parse(XML_PATH)
        services = root.getiterator("service")
        for service in services:
            if (service.attrib['name'] == info_file_dict['service'] and
                    service.attrib['resource_type']
                    == info_file_dict['resource_type']):
                return service
        return None

    def format_data(self, all_usage_dict, info_file_dict):
        '''
            Format the collected datas into result and defined format:
            {"metricDatas": [
                        {"metricName": "cpuUsage",
                         "dimensions": "ip=1.1.1.1",
                         "aggregationDimensions": "cluster=c1,env=prod",
                         "sum": 101,
                         "maxinum": 101,
                         "mininum": 101,
                         "sampleCount": 1,
                         "createTime": 1344329292557,
                         "unit": null
                         }
                      ]
            }
        '''
        metric_datas = dict()
        metric_datas['metricDatas'] = list()
        identify_id = self._get_identify_id(info_file_dict)
        service = self._get_service_from_xml(info_file_dict)
        if service is None:
            return metric_datas
        metrics = service.getiterator('metric')
        for metric in metrics:
            metric_type = metric.attrib['name']
            metric_unit = metric.attrib['unit']
            func = self._get_aggregation_dimensions_for_metric
            aggregationDimensions = func(metric, info_file_dict)
            if metric_type == 'diskPartition':
                name = self._get_monitor_partition_types(metric)
                self._get_partition_usage(metric_datas,
                                          info_file_dict,
                                          all_usage_dict,
                                          metric_type, name,
                                          aggregationDimensions,
                                          identify_id,
                                          service)
            elif metric_type == 'netCardsFlowRate':
                self._get_netcards_flowrate_usage(metric_datas,
                                                  all_usage_dict[metric_type],
                                                  aggregationDimensions,
                                                  identify_id)
            elif metric_type:
                dimensions = (info_file_dict['resource_type'] + '=' +
                        identify_id)
                metric_data = self._setting_params(metric_type,
                                                   dimensions,
                                                   aggregationDimensions,
                                                   all_usage_dict[metric_type],
                                                   metric_unit)
                metric_datas['metricDatas'].append(metric_data)

        return metric_datas


class SendRequest(object):
    '''
        Send datas to monitor server by accesskey authorization.
    '''
    def __init__(self, info_file_dict, metric_datas_json=None,
                 request_uri='/rest/V1/MetricData',
                 headers={'Content-type': 'application/x-www-form-urlencoded'},
                 http_method='POST',
                 system_partitions=None,
                 logic_partitions=None,
                 parti_dimension=None):
        self.url = info_file_dict['monitorWebServerUrl']
        self.request_uri = request_uri
        self.headers = headers
        self.http_method = http_method
        self.project_id = info_file_dict['ori_user']
        self.name_space = info_file_dict['service']
        self.access_key = info_file_dict['accessKey']
        self.access_secret = info_file_dict['accessSecret']
        self.metric_datas_json = metric_datas_json
        self.system_partitions = system_partitions
        self.logic_partitions = logic_partitions
        self.parti_dimension = parti_dimension

    def send_request_to_server(self):
        '''
            Send monitor datas to collect server by POST request.
        '''
        params_dict = {
                'ProjectId': self.project_id,
                'Namespace': self.name_space,
                'AccessKey': self.access_key,
                'Signature': self.generate_signature()
        }
        if self.metric_datas_json != None:
            params_dict['MetricDatasJson'] = self.metric_datas_json
        if self.system_partitions != None:
            params_dict['SystemPartitions'] = self.system_partitions
        if self.logic_partitions != None:
            params_dict['LogicPartitions'] = self.logic_partitions
        if self.parti_dimension != None:
            params_dict['Dimension'] = self.parti_dimension
        params = urllib.urlencode(params_dict)

        if str(self.url).startswith('http://'):
            self.url = str(self.url).split("http://")[-1]
        conn = httplib.HTTPConnection(self.url, timeout=3)
        conn.request(self.http_method, self.request_uri, params, self.headers)
        response = conn.getresponse()
        conn.close()
        return response

    def generate_stringToSign(self):
        '''
            Generate stringToSign for signature.
        '''
        canonicalized_headers = ''
        if self.metric_datas_json != None:
            canonicalized_resources = ('AccessKey=%s&MetricDatasJson=%s&'
                                       'Namespace=%s&ProjectId=%s' %
                                    (self.access_key, self.metric_datas_json,
                                     self.name_space, self.project_id))
        elif self.system_partitions != None:
            canonicalized_resources = ('AccessKey=%s&Dimension=%s&'
                                       'LogicPartitions=%s&Namespace=%s&'
                                       'ProjectId=%s&SystemPartitions=%s' %
                                       (self.access_key, self.parti_dimension,
                                        self.logic_partitions, self.name_space,
                                        self.project_id,
                                        self.system_partitions))
        else:
            raise Exception()

        StringToSign = '%s\n%s\n%s\n%s\n' % \
                      (self.http_method, self.request_uri,
                       canonicalized_headers, canonicalized_resources)

        return StringToSign

    def generate_signature(self):
        '''
            Generate signature for authorization.
            Use hmac SHA-256 to calculate signature string and encode
            into base64.
            @return String
        '''
        stringToSign = self.generate_stringToSign()
        hashed = hmac.new(str(self.access_secret), stringToSign,
                          hashlib.sha256)
        s = hashed.digest()
        signature = s.encode('base64').rstrip()
        return signature


if __name__ == '__main__':

    try:
        info_file_dict = read_info_file()
        metadata_result = handle_metadata(info_file_dict)
        temp_result = read_temp_file()

        get_system_usage = GetSystemUsage()
        all_usage_dict = get_system_usage.get_system_usage_datas()
        write_temp_file()

        if temp_result == True and metadata_result == True:
            metric_datas = DataFormater().format_data(all_usage_dict,
                                                      info_file_dict)
            metric_datas_json = json.dumps(metric_datas)
            send_request = SendRequest(info_file_dict, metric_datas_json)
            send_request.send_request_to_server()
    except Exception:
        pass
