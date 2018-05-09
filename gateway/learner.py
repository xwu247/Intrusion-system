#!/usr/bin/python
# title            :learn.py
# author           :Xuan, Alex, Ruoyu
# description      :learning script running on switch for learning device profile
# date             :01-01-2018
# ==============================================================================
from scapy.all import *
import argparse
import time
import threading
from threading import Semaphore
import pickle
import numpy as np
from db_config.mongo_ops import *
from pprint import pprint
from utils import *
from upload_download.upload import upload
from collections import defaultdict
import os
import shutil

FR = 0
TO = 1


# helper function for debug mode
# parse device_list.txt configuration file
def get_device_list(filename):
    device_list = list()
    with open((filename), "r") as f:
        contents = f.read()
    if contents:
        device_list = contents.split('\n')
        device_list = list(filter(None, device_list))
    device_list = [s.strip() for s in device_list if s.startswith('#') == False]
    return device_list


# Packet Call Back function
def get_target_traffic(iter_seq):
    def filter(pkt):

        def update_comms(ip, mac, endpt_ip, direction, protocol, sport, dport):
            """
            function to update database and device profile based on general traffic
            """
            # no use, because only ips already in ip_addr can call update_comms fucntion, so new ip can't get here
            device_dict = dict()
            device_dict['mac_address'] = mac
            device_dict['ip_address'] = ip
            domains = []
            device_dict['domains'] = domains
            endpts = [create_endpoint(endpt_ip, -1, None)]
            device_dict['endpts'] = endpts

            if not device_exists(device_dict):
                print("Found new device but no from DHCP")
                add_device(device_dict)
            else:
                print("Device found, update endpoint")
                print("endpoint ip: %s" % endpt_ip)
                update_device_endpts(device_dict['mac_address'], endpt_ip, direction, protocol, sport, dport)

        global addr_list
        # Parsing DHCP transaction
        try:
            standard_dns_callback(pkt, dns_query_dict, dns_list)
        except Exception as e:
            print("Error: Parsing DNS transaction")
            pass

        # Parsing DNS transaction
        try:
            standard_dhcp_callback(pkt, dhcp_trans_history, exception_ip)
        except Exception as e:
            print("Error: Parsing DHCP transaction")
            pass

        # Cannot handle ARP or other None IP protocols for now
        if not pkt.getlayer(IP):
            return

        # Comment this out for debug mode
        # addr_list = get_ip_list()

        # Exception list
        layers = list(layer_expand(pkt))
        if pkt.getlayer(IP).src in exception_ip:
            return

        # add ip when DHCP ACK doesn't appear

        # Update device database and profile save traffic
        if pkt.getlayer(IP).src in addr_list:
            protocol = pkt.proto
            if protocol == 6 or protocol == 17:
                    sport = pkt.sport
                    dport = pkt.dport
            else:
                sport = -1
                dport = -1
            # statistics
            update_protocol_stats(pkt[Ether].src, protocol, len(pkt[IP]))
            update_service_stats(pkt[Ether].src, sport, dport, len(pkt[IP].payload))
            update_device_in_ex_stats(pkt[Ether].src, pkt.getlayer(IP).dst, len(pkt[IP]))
            if DNS not in pkt and 'BOOTP' not in layers:
                update_comms(pkt.getlayer(IP).src, pkt[Ether].src, pkt.getlayer(IP).dst, FR, protocol, sport,
                                 dport)
                if not os.path.exists("./pcap/cap_" + str(iter_seq)):
                    os.mkdir("./pcap/cap_" + str(iter_seq))
                wrpcap('./pcap/cap_' + str(iter_seq) + '/cap_' + pkt.getlayer(IP).src + '.pcap', pkt, append=True)
            else:
                pass

        elif pkt.getlayer(IP).dst in addr_list:
            protocol = pkt.proto
            if protocol == 6 or protocol == 17:
                    sport = pkt.sport
                    dport = pkt.dport
            else:
                sport = -1
                dport = -1
            # statistics
            update_protocol_stats(pkt[Ether].dst, protocol, len(pkt[IP]))
            update_service_stats(pkt[Ether].dst, sport, dport, len(pkt[IP].payload))
            update_device_in_ex_stats(pkt[Ether].dst, pkt.getlayer(IP).src, len(pkt[IP]))
            if DNS not in pkt and 'BOOTP' not in layers:
                update_comms(pkt.getlayer(IP).dst, pkt[Ether].dst, pkt.getlayer(IP).src, TO, protocol, sport,
                             dport)
                if not os.path.exists("./pcap/cap_" + str(iter_seq)):
                    os.mkdir("./pcap/cap_" + str(iter_seq))
                wrpcap('./pcap/cap_' + str(iter_seq) + '/cap_' + pkt.getlayer(IP).src + '.pcap', pkt, append=True)
            else:
                pass

        # elif pkt.getlayer(IP).dst in addr_list:
        #     if not DNS in pkt and not 'BOOTP' in layers:
        #         update_comms(pkt.getlayer(IP).dst, pkt[Ether].dst, pkt.getlayer(IP).src)
        #         wrpcap('./cap_' + str(iter_seq) + '/cap_' + pkt.getlayer(IP).dst + '.pcap', pkt, append=True)
        else:
            # Uninterested traffic
            pass
        addr_list = get_ip_list()

    return filter


def capture_traffic(iter_seq):
    start_time = time.time()
    # Choose proper sniffing interface, time out parameter
    sniff(iface='enxa0cec8c0b2fb',timeout=10, prn=get_target_traffic(iter_seq))
    print("capture traffic takes %f seconds" % (time.time() - start_time))


# helper function for debug mode
def get_devices_from_file(filename):
    with open(filename, "r") as f:
        contents = f.read()
    if contents:
        device_items = contents.split('\n')
        device_items = list(filter(None, device_items))
    else:
        raise e

    device_ip_mac_list = [s.strip().split(',') for s in device_items]
    ip_list = [pair[0] for pair in device_ip_mac_list]
    mac_list = [pair[1] for pair in device_ip_mac_list]
    return device_ip_mac_list, ip_list, mac_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--time", help="the period to run the learner", default="600")
    parser.add_argument("--debug", default="False")

    args = parser.parse_args()

    global debug_var
    global exception_ip
    global addr_list
    exception_ip = get_device_list('device_exception.txt')

    if args.debug == "False":
        debug_var = False
        addr_list = get_ip_list()

    elif args.debug == "True":
        debug_var = True
        ips_macs, ips, macs = get_devices_from_file('device_list.txt')
        print("add hardcoded list of ips", ips_macs)
        for ip, mac in ips_macs:
            device_dict = dict()
            device_dict['mac_address'] = mac
            device_dict['ip_address'] = ip
            domains = []
            device_dict['domains'] = domains
            endpts = []
            # endpts.append(pkt.getlayer(IP).dst)
            device_dict['endpts'] = endpts
            if not device_exists(device_dict):
                add_device(device_dict)
            try:
                discover_message = "Discovered;" + ip
                channel.basic_publish(exchange='', routing_key='deviceip', body=discover_message)
            except Exception as e:
                print("Error: Cannot connect to web server")
                pass

    window_time = int(args.time)
    global num_iter
    num_iter = window_time / 10

    global dns_query_dict
    global dns_list
    dns_query_dict = dict()
    dns_list = dict()

    global dhcp_trans_history
    global dhcp_list
    dhcp_trans_history = defaultdict(lambda: [])

    print("Initiate Data Capture")

    for i in range(num_iter):
        
       # if not os.path.exists('./cap_'+str(i)):
           # os.makedirs('./cap_'+str(i))
       # try:
           # capture_traffic(ips, i)
       # except Exception as e:
           # print("uncaught parsing error during traffic capturing")
           # pass

        capture_traffic(i)

        backup_filename = './cap_' + str(i)
        print(backup_filename)
