#!/usr/bin/python
# title            :utils.py
# author           :Xuan, Alex, Ruoyu
# description      :useful function for DHCP DNS Fingerbank Static Profile parsing
# date             :01-01-2018
# ==============================================================================
from __future__ import print_function
from scapy.all import *
import argparse
import json
import requests
import imp
from db_config.mongo_ops import *
from static_profile.mud_controller import *
from collections import defaultdict
from fingerbank_key import *

manuf = imp.load_source("manuf", "manuf/manuf/manuf.py")
from manuf import main
import pika, os, logging
import csv

logging.basicConfig()

# The following block are for web app
# Parse CLODUAMQP_URL
url = 'amqp://unmntdbc:cOLaTd5JrnOdbxMSnVUwABRAZRZhXSlZ@fish.rmq.cloudamqp.com/unmntdbc'
# params = pika.URLParameters(url)
# params.socket_timeout = 5
# Connect to CloudAMQP
# connection = pika.BlockingConnection(params)
# start a channel
# channel = connection.channel()
# Declare a queue
# channel.queue_declare(queue='deviceip')

non_iot_os = ['Windows OS', 'Mac OS X']


def layer_expand(packet):
    yield packet.name
    while packet.payload:
        packet = packet.payload
        yield packet.name


# Parsing DHCP Discover packet and use Fingerbank API for device information
# Please refer to Lalka's work for more details
def get_device_dhcp_info(pkt):
    features = {'mac_address': "", 'manufacturer': "", 'os': "", \
                'device_type': "", 'IoT': True, 'static_profile': []}
    req_list = []

    try:
        features['mac_address'] = hex_mac(pkt[BOOTP].chaddr)
    except Exception as e:
        features['mac_address'] = pkt.src

    if features['mac_address'] != pkt.src:
        print('Src mac address mismatches with DHCP messages')
    features['manufacturer'] = query_oui(features['mac_address'])

    try:
        options = pkt[BOOTP][DHCP].options
    except Exception as e:
        try:
            options = pkt['BOOTP']['DHCP'].options
        except Exception as e:
            raise e

    for option in options:
        if type(option) is tuple:
            opt_name = option[0]
            opt_value = option[1]
            if opt_name == 'param_req_list':
                for b in str(opt_value):
                    req_list.append(ord(b))
                t, v = query_fingerbank(req_list)
                if t == "Operating System":
                    features['os'] = v
                    if v in non_iot_os:
                        features['IoT'] = False
                else:
                    if t != "":
                        features['device_type'] = v
                        if v.find('Printer') != -1:
                            features['IoT'] = True

            # if opt_name == 'hostname':
            #     if opt_value.find('iPhone') != -1:
            #         features['device_type'] = "iPhone"
            #         features['IoT'] = False
            #     if opt_value.find('iPad') != -1:
            #         features['device_type'] = "iPad"
            #         features['IoT'] = False
            #     if opt_value.find('android') != -1:
            #         features['device_type'] = "Android"
            #         features['IoT'] = False
            #     if opt_value.find('Windows-Phone') != -1:
            #         features['device_type'] = "Windows-Phone"
            #         features['IoT'] = False
            #     if opt_value.find('BLACKBERRY') != -1:
            #         features['device_type'] = "BLACKBERRY"
            #         features['IoT'] = False

            if opt_name == 161:
                print(opt_value)
                ver = radius(opt_value)
                if ver == 0:
                    features['static_profile'] = read_json()
                else:
                    features['static_profile'] = ["QUARANTINE"]

    print(features)
    print("")

    return features


def query_oui(addr):
    p = manuf.MacParser()
    return p.get_manuf(addr)


def hex_mac(chaddr):
    MAC = ""
    for b in str(chaddr):
        digit = hex(ord(b))
        digit = digit.split('x', 1)[1]
        if len(digit) == 1:
            MAC += "0"
        MAC += digit
        MAC += ":"
    return MAC[: 17]


def query_fingerbank(req_list):
    headers = {'Content-Type': 'application/json'}
    url = 'https://api.fingerbank.org/api/v2/combinations/interrogate?key=' \
          + fingerbank_key_val
    str1 = ','.join(str(e) for e in req_list)
    params = {'dhcp_fingerprint': str1}

    resp = requests.get(url, headers=headers, params=params)
    info = resp.json()
    try:
        err = info['errors']
        print(err)
        return "", ""
    except KeyError:
        device_name = info['device_name']
        t = device_name.split('/', 1)[0]
        return t, info['device']['name']


def check_dhcp_type(pkt):
    if pkt[BOOTP][DHCP].options[0][0] == 'message-type':
        if pkt[BOOTP][DHCP].options[0][1] == 1:
            return 'DISCOVER'
        if pkt[BOOTP][DHCP].options[0][1] == 2:
            return 'OFFER'
        if pkt[BOOTP][DHCP].options[0][1] == 3:
            return 'REQUEST'
        if pkt[BOOTP][DHCP].options[0][1] == 4:
            return 'DECLINE'
        if pkt[BOOTP][DHCP].options[0][1] == 5:
            return 'ACK'
        if pkt[BOOTP][DHCP].options[0][1] == 6:
            return 'NAK'
        if pkt[BOOTP][DHCP].options[0][1] == 7:
            return 'RELEASE'
        if pkt[BOOTP][DHCP].options[0][1] == 8:
            return 'INFORM'
    else:
        return 'NOT DHCP'


# DNS packet parsing
def dns_callback(pkt, dns_query_history, dns_list):
    # Query Packet, Store transaction
    if DNS in pkt and 'Qry' in pkt.summary():
        dns_query_history[pkt[DNS].id] = (pkt[IP].src, pkt[IP].dst)
        return

    # Answer Packet, read answer and pop the transaction
    if DNS in pkt and 'Ans' in pkt.summary():
        trans_id = pkt[DNS].id
        try:
            struct = dns_query_history[trans_id]
        except Exception as e:
            return

        if dns_query_history[trans_id]:

            src, dst = dns_query_history[trans_id]

            if pkt[IP].dst != src and pkt[IP].src != dst:
                raise e

            responses = []

            for x in xrange(pkt[DNS].ancount):
                # print(pkt[DNSRR][x].rdata)
                responses.append(pkt[DNSRR][x].rdata)

            try:
                dns_list[pkt[DNSQR].qname] = responses
                device_dict = dict()
                device_dict['mac_address'] = pkt[Ether].dst
                device_dict['ip_address'] = pkt.getlayer(IP).dst

                endpts = []
                domains = []

                domain_dict = dict()
                domain_dict['domain'] = pkt[DNSQR].qname
                domain_dict['ips'] = responses
                domains.append(domain_dict)

                device_dict['endpts'] = endpts
                device_dict['domains'] = domains

                if not device_exists(device_dict):
                    pass
                else:
                    # Device exits
                    update_device_domains(device_dict['mac_address'], domain_dict)
            except Exception as e:
                print('Error: Parsing DNS packet error')
                return

            try:
                dns_query_history.pop(trans_id)
            except Exception as e:
                print('Error: DNS transations_id should exists !')
                raise e
        else:
            print(" Key error:  ", pkt[DNS].id)
            pass


def standard_dns_callback(pkt, dns_query_history, dns_list):
    layers = list(layer_expand(pkt))
    if 'DNS' in layers:
        dns_callback(pkt, dns_query_history, dns_list)
        return dns_query_history, dns_list

    # DNS parsing function, for monitoring stage


def monitor_dns(pkt, dns_query_history, dns_list):
    if DNS in pkt and 'Qry' in pkt.summary():
        dns_query_history[pkt[DNS].id] = (pkt[IP].src, pkt[IP].dst)
        return

    if DNS in pkt and 'Ans' in pkt.summary():
        trans_id = pkt[DNS].id
        try:
            struct = dns_query_history[trans_id]
        except Exception as e:
            return

        if dns_query_history[trans_id]:
            src, dst = dns_query_history[trans_id]

            if pkt[IP].dst != src and pkt[IP].src != dst:
                raise e

            responses = []

            for x in xrange(pkt[DNS].ancount):
                # print(pkt[DNSRR][x].rdata)
                responses.append(pkt[DNSRR][x].rdata)

            try:
                # if True:
                dns_list[pkt[DNSQR].qname] = responses
                device_dict = dict()
                device_dict['mac_address'] = pkt[Ether].dst
                device_dict['ip_address'] = pkt.getlayer(IP).dst
                endpts = []
                domains = []
                domain_dict = dict()
                domain_dict['domain'] = pkt[DNSQR].qname
                domain_dict['ips'] = responses
                domains.append(domain_dict)
                device_dict['endpts'] = endpts
                device_dict['domains'] = domains
                if check_domain_valid(device_dict['mac_address'], domain_dict['domain']):
                    update_device_domains(device_dict['mac_address'], domain_dict)
                else:
                    print("anomaly detected src:" + pkt.getlayer(IP).src + ".... dst:" + response[-1])
                    anomaly_message = "Anomaly;" + pkt.getlayer(IP).src + ";" + responses[-1]
                    channel.basic_publish(exchange='', routing_key='deviceip', body=anomaly_message)

            except Exception as e:
                # This happens because the computation latency
                # We might already miss the packets
                # while the thread is executing parsing routine
                print('Warning:DNS Callback error')

                pass
            try:
                dns_query_history.pop(trans_id)
            except Exception as e:
                print('Error: transations_id should exists !')
                raise e
        else:
            print(" Key error:  ", pkt[DNS].id)
            return


def monitor_dns_callback(pkt, dns_query_history, dns_list):
    layers = list(layer_expand(pkt))
    if 'DNS' in layers:
        monitor_dns(pkt, dns_query_history, dns_list)
        return dns_query_history, dns_list


# DHCP Packet parsing
def standard_dhcp_callback(pkt, dhcp_msgs_dict, exception_list=None):
    layers = list(layer_expand(pkt))
    if 'BOOTP' in layers:

        # Discover message parsing, store transacation
        if check_dhcp_type(pkt) == 'DISCOVER':
            print("DHCP DISCOVER Observed")
            dhcp_msgs_dict[pkt[Ether].src].append(('DISCOVER', pkt.time))
            device = None
            device = get_device_dhcp_info(pkt)

            if device:
                device_dict = dict()
                device_dict['mac_address'] = pkt[Ether].src
                endpts = []
                domains = []
                protocol_stats = []
                service_stats = []
                in_ex_stats = {}
                device_dict['endpts'] = endpts
                device_dict['domains'] = domains
                device_dict['protocol_stats'] = protocol_stats
                device_dict['service_stats'] = service_stats
                device_dict['in_ex_stats'] = in_ex_stats
                device_dict['IoT'] = device['IoT']
                device_dict['manufacturer'] = device['manufacturer']
                device_dict['os'] = device['os']
                device_dict['device_type'] = device['device_type']
                device_dict['static_profile'] = device['static_profile']
                if not device_exists(device_dict):
                    print("Found DHCP Discover, non existing device, Adding to database")
                    add_device(device_dict)
            else:
                print("Error: Utils.py Failed to Query Fingerbank")

        elif check_dhcp_type(pkt) == 'OFFER':
            print("DHCP OFFER Observed")
            if dhcp_msgs_dict[pkt[Ether].dst]:
                print("DHCP Offer,  Update device IP  MAC ", pkt[IP].dst, pkt[Ether].dst)
                device = {'mac_address': pkt[Ether].dst}
                update_device_ip(device, pkt[IP].dst)
                dhcp_msgs_dict.pop(pkt[Ether].dst)
            else:
                pass

        elif check_dhcp_type(pkt) == 'REQUEST':
            print("DHCP REQUEST Observed")
            dhcp_msgs_dict[pkt[BOOTP].xid].append(('REQUEST', pkt.time))
            device = None
            device = get_device_dhcp_info(pkt)

            if device:
                device_dict = dict()
                device_dict['mac_address'] = pkt[Ether].src
                endpts = []
                domains = []
                protocol_stats = []
                service_stats = []
                in_ex_stats = {}
                device_dict['endpts'] = endpts
                device_dict['domains'] = domains
                device_dict['protocol_stats'] = protocol_stats
                device_dict['service_stats'] = service_stats
                device_dict['in_ex_stats'] = in_ex_stats
                device_dict['IoT'] = device['IoT']
                device_dict['manufacturer'] = device['manufacturer']
                device_dict['os'] = device['os']
                device_dict['device_type'] = device['device_type']
                device_dict['static_profile'] = device['static_profile']
                if not device_exists(device_dict):
                    print("Found DHCP Request, non existing device, Adding to database")
                    add_device(device_dict)
            else:
                print("Error: Utils.py Failed to Query Fingerbank")

        elif check_dhcp_type(pkt) == 'DECLINE':
            pass

        elif check_dhcp_type(pkt) == 'ACK':
            print("DHCP ACK Observed")
            if dhcp_msgs_dict[pkt[BOOTP].xid]:
                print("DHCP ACK,  Update device IP  MAC ", pkt[IP].dst, pkt[Ether].dst)
                device = {'mac_address': pkt[Ether].dst}
                update_device_ip(device, pkt[IP].dst)
                try:
                    discover_message = "Discovered;" + pkt[IP].dst
                    channel.basic_publish(exchange='', routing_key='deviceip', body=discover_message)
                except Exception as e:
                    pass
                dhcp_msgs_dict.pop(pkt[BOOTP].xid)
            else:
                pass

        elif check_dhcp_type(pkt) == 'NAK':
            pass
        elif check_dhcp_type(pkt) == 'RELEASE':
            pass
        elif check_dhcp_type(pkt) == 'INFORM':
            pass
