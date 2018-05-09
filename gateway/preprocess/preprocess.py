#!/usr/bin/python
from __future__ import print_function
from scapy.all import *
import argparse
import json

def layer_expand(packet):
    yield packet.name
    while packet.payload:
        packet = packet.payload
        yield packet.name


def get_dhcp_pkt_feat(sess):
    for pkt in sess:
        options = pkt[BOOTP][DHCP].options
        # HERE: Here is options
        print(options)
    pass

def get_dhcp_sessions(pkts):
    sess = pkts.sessions()
    for k,v in sess.iteritems():
        try:
            transport_layer_protocol, src, _, dst = k.split(" ")
            src, sport = src.split(":")
            dst, dport = dst.split(":")
        except Exception as e:
            # Other protocols ARP ICMP
            continue
        

        if (sport == "68" and dport=="67"):
            print("---------------------")
            print("DHCP Broadcast")
            print("--------------------")
            get_dhcp_pkt_feat(v)
            # print(sess[0])
        if (sport == "67" and dport=="68"):
            print("---------------------")
            print("DHCP Offer and Config")
            print("---------------------")
            # print(sess[1])
            get_dhcp_pkt_feat(v)
    # pkt[BOOTP][DHCP]

    return 1


def get_sessions(pkts):
    nodes_communications = dict()
    sess = pkts.sessions()

    for k, v in sess.iteritems():
        five_tuples = k.split(" ")
        # print(k)
        try:
            transport_layer_protocol, src, _, dst = five_tuples
            src, sport = src.split(":")
            dst, dport = dst.split(":")
            layers = list(layer_expand(v[0]))
            if layers[-1] == "Raw":
                # print(layers[-2])
                nodes_communications[src] = (sport, dst, dport, layers[-2])
            else:
                # print(layers[-1])
                nodes_communications[src] = (sport, dst, dport, layers[-1])
        except Exception as e:
            # Other protocols ARP ICMP
            if five_tuples[0] == "ARP":
                nodes_communications[five_tuples[1]] = (None, five_tuples[3], None, five_tuples[0])
                continue
            if five_tuples[0] == "ICMP":
                # print("ICMP")
                nodes_communications[five_tuples[1]] = (None, five_tuples[3], None, five_tuples[0])
                continue
            if five_tuples[0] == "Ethernet":
                # print("Ethernet")
                continue
        if (sport == "68" and dport=="67"):
            print("---------------------")
            print("DHCP Broadcast")
            print("--------------------")
            get_dhcp_pkt_feat(v)
            # print(sess[0])
        if (sport == "67" and dport=="68"):
            print("---------------------")
            print("DHCP Offer and Config")
            print("---------------------")
            # print(sess[1])
            get_dhcp_pkt_feat(v)
            
    # key is src IP, value is sport, dst, dport, protocol
    print(nodes_communications)

        

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapfile", help="pcap file for traffic")
    
    args = parser.parse_args()
    packets = rdpcap(args.pcapfile)
    
    get_sessions(packets)
    