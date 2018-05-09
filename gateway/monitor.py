#!/usr/bin/python
#title            :monitor.py
#author           :Xuan, Alex, Ruoyu
#description      :monitor scripts running on switch (default gateway) for capturing traffic,
#                  monitoring devices network activities
#date             :01-01-2018
#==============================================================================
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

import pika, os, logging
logging.basicConfig()

# Following block is for web application
# Comment out if unnecessary
# Parse CLODUAMQP_URL
url = 'amqp://unmntdbc:cOLaTd5JrnOdbxMSnVUwABRAZRZhXSlZ@fish.rmq.cloudamqp.com/unmntdbc'
params = pika.URLParameters(url)
params.socket_timeout = 5
# Connect to CloudAMQP
connection = pika.BlockingConnection(params) 
# start a channel
channel = connection.channel() 
# Declare a queue
channel.queue_declare(queue='deviceip') 



# helper function for debug mode
# parse device_list.txt file
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
def get_target_traffic(addr_list, iter_seq):

    def filter(pkt):
        def update_comms_and_monitor(src_ip, src_mac, dst_ip):
            device_dict = dict()
            device_dict['mac_address'] = src_mac
            device_dict['ip_address'] = src_ip
            
            if not device_exists(device_dict):
                print("a uncaught loose device", device_dict['mac_address'], device_dict['ip_address'])
                try:
                    discover_message = "Discovered;" + pkt[IP].src
                    channel.basic_publish(exchange='', routing_key='deviceip', body=discover_message)
                except Exception as e:
                    print("Error: Connection to Web server failed")
                    pass
            
            else:
                # Device exists in database
                if not check_valid(device_dict, dst_ip):
                    print("anomaly detected src:" + src_ip + ".... dst:" + dst_ip)
                    try:
                        anomaly_message = "Anomaly;" + src_ip + ";" + dst_ip
                        channel.basic_publish(exchange='', routing_key='deviceip', body=anomaly_message)
                    except Exception as e:
                        print("Error: Connection to Web server failed")
                        pass
            return
        
        # Parse DNS packet
        try:
            monitor_dns_callback(pkt, dns_query_dict, dns_list)
        except Exception as e:
            print("Error: Parsing DNS transactions")
            pass
        
        # Parse DHCP packet
        try:
            standard_dhcp_callback(pkt, dhcp_trans_history, exception_ip)
        except Exception as e:
            print("Error: Parsing DHCP message error")
            pass
        
        # Cannot handle none IP protocols
        if pkt.getlayer(IP) == None:
            return

        # Comment the following line out for debug mode
        addr_list = get_ip_list()

        layers = list(layer_expand(pkt))
        if pkt.getlayer(IP).src in exception_ip:
            return
        if pkt.getlayer(IP).dst in exception_ip:
            return       
        
        if pkt.getlayer(IP).src in addr_list:
            if not DNS in pkt and not 'BOOTP' in layers:
                update_comms_and_monitor(pkt.getlayer(IP).src, pkt[Ether].src, pkt[IP].dst)
                wrpcap('./pcap/cap_' + str(iter_seq) + '/cap_' + pkt.getlayer(IP).src + '.pcap', pkt, append=True)

        # elif pkt.getlayer(IP).dst in addr_list:
        #     if not DNS in pkt and not 'BOOTP' in layers:
        #         update_comms_and_monitor(pkt.getlayer(IP).dst, pkt[Ether].dst, pkt.getlayer(IP).src)
        #         wrpcap('./cap_' + str(iter_seq) + '/cap_' + pkt.getlayer(IP).dst + '.pcap', pkt, append=True)
        
        else:
            # Uninterested traffic
            pass

    return filter

def capture_traffic(addr_list,  iter_seq):
    start_time = time.time()
    # Choose proper interface and time out parameter
    sniff(iface='enxb827eb628ead', timeout=10, prn=get_target_traffic(addr_list,  iter_seq))
    print("capture traffic takes %f seconds" % (time.time() - start_time))

def get_devices_from_file(filename):
    with open(filename, "r") as f:
        contents = f.read()
    if contents:
        device_items = contents.split('\n')
        device_items = list(filter(None, device_items))
    else:
        raise e

    device_ip_mac_list = [s.strip().split(',') for s in device_items]
    ip_list = [ pair[0] for pair in device_ip_mac_list]
    mac_list = [ pair[1]  for pair in device_ip_mac_list]
    return device_ip_mac_list, ip_list, mac_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--time", help="the period to run the learner", default="600")
    parser.add_argument("--debug", default="False")

    args = parser.parse_args()

    global exception_ip
    exception_ip = get_device_list('device_exception.txt')

    global debug_var
    if args.debug == "False":
        debug_var = False
        ips = get_ip_list()

    elif args.debug == "True":
        debug_var = True
        
        ips_macs, ips, macs = get_devices_from_file('device_list.txt')

        print("add hardcoded list of ips",  ips_macs)

        for ip, mac in ips_macs:
            device_dict = dict()
            device_dict['mac_address'] = mac
            device_dict['ip_address'] = ip
            
            domains = []
            device_dict['domains'] = domains
            
            endpts = []
            device_dict['endpts'] = endpts
            
            if not device_exists(device_dict):
                
                print("adding hardcoded device to database")
                
                add_device(device_dict)
                
                try:
                    discover_message = "Discovered;"+pkt[IP].dst
                    channel.basic_publish(exchange='', routing_key='deviceip', body=discover_message)
                except Exception as e:
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

        if not os.path.exists('./cap_'+str(i)):
            os.makedirs('./cap_'+str(i))
        try:  
            capture_traffic(ips, i)
        except Exception as e:
            pass
        
        backup_filename = './cap_'+str(i)
        print(backup_filename)
        upload(backup_filename, 'traffic', i)



