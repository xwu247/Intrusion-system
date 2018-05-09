#!/usr/bin/python
# title            :mongo_ops.py
# author           :Alex, Ruoyu
# description      :mongoDB query api
# date             :01-01-2018
# ==============================================================================
from pymongo import MongoClient
from pprint import pprint

client = MongoClient('localhost', 27017)
# cloud db
# client = MongoClient("mongodb://IRTLab:iotsecurity@ \
#                     irtcluster-shard-00-00-j79ga.mongodb.net:27017, \
#                     irtcluster-shard-00-01-j79ga.mongodb.net:27017, \
#                     irtcluster-shard-00-02-j79ga.mongodb.net:27017/test? \
#                     ssl=true&replicaSet=IRTCluster-shard-0&authSource=admin")

db = client['traffic-db']
flow_stats = db['flow_stats']
session_stats = db['session_stats']
one_way_stats = db['one_way_stats']
devices = db['devices']

FR = 0
TO = 1


def is_endpt_domain(device, endpt_ip):
    domains = device['domains']
    for domain in domains:
        if endpt_ip in domain['ips']:
            return True
    return False


def create_trans(protocol, sport, dport):
    trans = dict()
    trans['protocol'] = protocol
    trans['sport'] = sport
    trans['dport'] = dport
    return trans


def create_endpoint(endpt_ip, direction, trans):
    endpt = dict()
    endpt['ip'] = endpt_ip
    endpt['fr'] = []
    endpt['to'] = []
    if direction == FR:
        endpt['fr'].append(trans)
    elif direction == TO:
        endpt['fr'].append(trans)
    elif direction == -1:
        pass
    return endpt


def update_device_endpts(mac_address, endpt_ip, direction, protocol, sport, dport):
    """
    endpts format:
    endpts =
        [
            {
                key1: 'ip'
                value1: string, ip of endpoint
                key2: 'fr'
                value2: [
                            {
                                key1: 'protocol'
                                value1: int, either 6-TCP or 17-UDP or -1-others
                                key2: 'sport'
                                value1: int, source port
                                key3: 'dport'
                                value3: int, destination port
                            },
                            {
                                ...
                            }
                        ]
                key3: 'to'
                value3: same format(list of dict) as value2
            },
            {
                ...
            }
        ]
    """
    device = devices.find_one({'mac_address': mac_address})
    is_domain = is_endpt_domain(device, endpt_ip)
    endpts = device['endpts']
    trans = create_trans(protocol, sport, dport)
    ip_exist = 0
    for endpt in endpts:
        if endpt_ip == endpt['ip']:
            ip_exist = 1
            trans_exist = 0
            if direction == FR:
                trans_list = endpt['fr']
            elif direction == TO:
                trans_list = endpt['to']
            for t in trans_list:
                if t['protocol'] == protocol and t['sport'] == sport and t['dport'] == dport:
                    trans_exist = 1
            if not trans_exist:
                trans_list.append(trans)
    if not ip_exist:
        endpt = create_endpoint(endpt_ip, direction, trans)
        endpts.append(endpt)
    devices.update({'mac_address': mac_address}, {'$set': {'endpts': endpts}})


def update_device_domains(mac_address, domain_dict):
    """
    domains format:
    domains =
        [
            {
                key1: domain
                value1: string, domain name
                key2: ips
                value2: [
                            ip bound with this domain name,
                           ...
                        ]
            },
            ...
        ]
    """
    device = devices.find_one({'mac_address': mac_address})
    domains = device['domains']
    for domain in domains:
        if domain['domain'] == domain_dict['domain'] and domain['ips'] != domain_dict['ips']:
            domain['ips'] = domain_dict['ips']
    devices.update({'mac_address': mac_address}, {'$set': {'domains': domains}})

    if domain_dict not in domains:
        domains.append(domain_dict)
        devices.update({'mac_address': mac_address}, {'$set': {'domains': domains}})


def add_device(device):
    devices.insert_one(device)


def check_domain_valid(mac_address, domain_name):
    device = devices.find_one({'mac_address': mac_address})
    domains = device['domains']
    # print(domains)
    for domain in domains:
        if domain == domain_name:
            return True
    return False


def query_devices():
    """
    Query database to get all devices
    :return: a list of all devices, each device is a dict
    """
    return devices.find()


def device_exists(device):
    mac_address = device['mac_address']
    if not devices.find_one({'mac_address': mac_address}):
        return False
    else:
        return True


def device_is_IoT(device):
    mac_address = device['mac_address']
    device = devices.find_one({'mac_address': mac_address})
    if device['IoT']:
        return True
    else:
        return False


def update_device_ip(device, ip):
    mac_address = device['mac_address']
    devices.update({'mac_address': mac_address}, {'$set': {'ip_address': ip}})


def check_valid(device, endpt_ip):
    existing_device = devices.find_one({'mac_address': device['mac_address']})
    if device['ip_address'] != existing_device['ip_address']:
        # print("duplicate mac address")
        return False

    if is_endpt_domain(existing_device, endpt_ip):
        return True

    for endpt in existing_device['endpts']:
        if endpt_ip == endpt['ip']:
            return True

    return False


def get_ip_list():
    devices = query_devices()
    device_list = []

    for device in devices:
        ip = None
        iot = True
        try:
            ip = device['ip_address']
        except Exception as e:
            continue
        try:
            iot = device['IoT']
        except Exception as e:
            pass

        if not iot:
            continue

        if ip:
            device_list.append(ip)

    return device_list


def get_device_manufacturer(device):
    mac_address = device['mac_address']
    device = devices.find_one({'mac_address': mac_address})
    try:
        manufacturer = device['manufacturer']
    except Exception:
        return None
    return manufacturer


def get_device_endpoints(device):
    mac_address = device['mac_address']
    device = devices.find_one({'mac_address': mac_address})
    endpoints = device['endpts']
    return endpoints


def get_device_domains(device):
    mac_address = device['mac_address']
    device = devices.find_one({'mac_address': mac_address})
    domains = device['domains']
    return domains


def get_mac_address(device):
    mac_address = device['mac_address']
    return mac_address


def update_protocol_stats(mac_address, protocol, payload):
    device = devices.find_one({'mac_address': mac_address})
    stats = device['protocol_stats']
    exist = 0
    if protocol == 1:
        protocol = 'ICMP'
    elif protocol == 6:
        protocol = 'TCP'
    elif protocol == 17:
        protocol = 'UDP'
    else:
        protocol = None

    if protocol:
        for s in stats:
            if s['protocol'] == protocol:
                s['payload'] += payload
                exist = 1
        if exist == 0:
            new_stat = dict()
            new_stat['protocol'] = protocol
            new_stat['payload'] = payload
            stats.append(new_stat)
        devices.update({'mac_address': mac_address}, {'$set': {'protocol_stats': stats}})


def update_service_stats(mac_address, sport, dport, payload):
    device = devices.find_one({'mac_address': mac_address})
    stats = device['service_stats']
    exist = 0
    if sport == -1 or dport == -1:
        service = None
    elif sport == 67 or sport == 68 or dport == 67 or dport == 68:
        service = 'DHCP'
    elif sport == 53 or dport == 53:
        service = 'DNS'
    elif sport == 80 or dport == 80:
        service = 'HTTP'
    elif sport == 443 or dport == 443:
        service = 'SSL'
    elif sport == 5222 or dport == 5222:
        service = 'XMPP'
    elif sport == 143 or dport == 143:
        service = 'IMAP'
    else:
        service = 'OTHER'

    if service:
        for s in stats:
            if s['service'] == service:
                s['payload'] += payload
                exist = 1
        if exist == 0:
            new_stat = dict()
            new_stat['service'] = service
            new_stat['payload'] = payload
            stats.append(new_stat)
        devices.update({'mac_address': mac_address}, {'$set': {'service_stats': stats}})


def update_device_in_ex_stats(mac_address, endpoint_ip, payload):
    device = devices.find_one({'mac_address': mac_address})
    stats = device['in_ex_stats']
    lo = 0
    if '192.168' in endpoint_ip:
        lo = 1

    new_stat = dict()
    if not stats:
        if lo:
            new_stat['in'] = payload
            new_stat['ex'] = 0
        else:
            new_stat['in'] = 0
            new_stat['ex'] = payload

        stats.update(new_stat)
    else:
        if lo:
            stats['in'] += payload
        else:
            stats['out'] += payload
    devices.update({'mac_address': mac_address}, {'$set': {'in_ex_stats': stats}})


# not used
def update_device(device):
    # ip address from dhcp
    devices.update({'mac_address': device['mac_address']}, {'$set': {'ip_address': device['ip_address']}})


def add_one_way(src, one_way):
    feature_dict = dict()
    feature_dict['src'] = str(src)
    feature_dict['endpoints'] = []
    for endpt in one_way[src]:
        endpt_dict = dict()
        endpt_dict['endpoint'] = endpt
        endpt_dict['stats'] = one_way[src][endpt]
        feature_dict['endpoints'].append(endpt_dict)
    one_way_stats.insert_one(feature_dict)


def update_one_way(src, old_one_way, new_one_way):
    src_one_way = one_way_stats.find_one({'src': src})
    endpoints = src_one_way['endpoints']
    for endpt in new_one_way[src]:
        for old_endpt in endpoints:
            try:
                if old_endpt['endpoint'] == endpt:
                    # need to test if this is right
                    continue
                elif old_endpt['stats']['domain'] == new_one_way[src][endpt]['domain']:
                    old_endpt['endpoint'] = endpt
                    continue
            except Exception as e:
                pass
            endpt_dict = dict()
            endpt_dict['endpoint'] = endpt
            endpt_dict['stats'] = new_one_way[src][endpt]
            endpoints.append(endpt_dict)
    one_way_stats.update({'src': src}, {'$set': {'endpoints': endpoints}})


def check_endpt_valid(mac_address, endpt):
    device = devices.find_one({'mac_address': mac_address})
    endpts = device['endpts']
    if not endpt in endpts:
        return False
    return True


def check_endpts_valid(one_way_stats):
    bad_endpts = []
    for src in one_way_stats:
        for endpt in one_way_stats[src]:
            if not check_endpt_valid(src, endpt):
                bad_endpts.append(endpt)
    return bad_endpts


def add_feature_extraction_to_db(feature_set):
    for feature in feature_set:
        if 'flow' in feature:
            feature_dict = dict()
            feature_dict[feature] = feature_set[feature]
            flow_stats.insert_one(feature_dict)
        elif feature == 'session_stats':
            print('sess')
            for src_dst in feature_set[feature]:
                feature_dict = dict()
                src = src_dst.split(',')[0]
                dst = src_dst.split(',')[1]
                feature_dict['src'] = src
                feature_dict['dst'] = dst
                # maybe?
                # endpt_dict['domain'] = feature_set[feature][src][endpt]['domain']
                feature_dict['stats'] = feature_set[feature][src_dst]
                session_stats.insert_one(feature_dict)
        elif feature == 'one_way_stats':
            print('one')
            for src in feature_set[feature]:
                feature_dict = dict()
                feature_dict['src'] = str(src)
                feature_dict['endpoints'] = []
                for endpt in feature_set[feature][src]:
                    endpt_dict = dict()
                    endpt_dict['endpoint'] = endpt
                    # maybe?
                    # endpt_dict['domain'] = feature_set[feature][src][endpt]['domain']
                    endpt_dict['stats'] = feature_set[feature][src][endpt]
                    feature_dict['endpoints'].append(endpt_dict)
                one_way_stats.insert_one(feature_dict)
        else:
            print('error')

            # for feat in flow_stats.find():
            #    pprint.pprint(feat)

            # for feat in session_stats.find():
            #    pprint.pprint(feat)

            # for feat in one_way_stats.find():
            #    pprint.pprint(feat)


def query_db():
    return flow_stats.find(), session_stats.find(), one_way_stats.find()


def query_all_flow_stats():
    return flow_stats.find()


def query_flow_stats(stat):
    for feat in flow_stats.find():
        if stat in feat:
            return feat[stat]


def query_all_sess_stats(src, dst):
    return session_stats.find_one({'src': src, 'dst': dst})


def query_sess_stats(src, dst, stat):
    return session_stats.find_one({'src': src, 'dst': dst})['stats'][stat]


def query_one_way_stats_src(src):
    return one_way_stats.find_one({'src': src})


def query_one_way_stats_src_dst(src, dst):
    one_way = one_way_stats.find_one({'src': src})
    for endpt in one_way['endpoints']:
        if endpt['endpoint'] == dst:
            return endpt['stats']


def query_one_way_stats_src_dst_stat(src, dst, stat):
    return query_one_way_stats_src_dst(src, dst)[stat]


def query_endpoints(src):
    one_way = one_way_stats.find_one({'src': src})
    endpoints = []
    for endpt in one_way['endpoints']:
        endpoints.append(endpt['endpoint'])
    return endpoints


def get_devices():
    devices = query_devices()
    device_list = []
    for device in devices:
        device_list.append(device)

    return device_list


def get_IoT():
    devices = query_devices()
    device_list = []
    for device in devices:
        if (device_is_IoT(device)):
            device_list.append(device)
    return device_list


def get_one_way(ip):
    one_way = one_way_stats.find_one({'src': ip})
    return one_way


def get_one_way_by_mac(mac):
    one_way = one_way_stats.find_one({'mac_address': mac})
    return one_way


def update_one_way_ip(device, new_ip):
    mac_address = device['mac_address']
    one_way_stats.update({'mac_address': mac_address}, {'$set': {'src': new_ip}})


def ip_in_device_db(ip):
    if not devices.find_one({'ip_address': ip}):
        return False
    return True


def ip_in_one_way_db(ip):
    if not one_way_stats.find_one({'src': ip}):
        return False
    return True


def get_device(ip):
    return devices.find_one({'ip_address': ip})


def update_one_way_db(one_way):
    for src in one_way:
        if not ip_in_one_way_db(src):
            add_one_way(src, one_way)
        else:
            current = query_one_way_stats_src(src)
            update_one_way(src, one_way, current)
