from scapy.all import *
import argparse
import json

def get_endpoint_comms(pkts):
    nodes_ip_comms = dict()
    nodes_dns_comms = dict()
    dns_responses = []
    for pkt in pkts:
        if DNS in pkt and ('Ans' in pkt.summary()):
            for x in range(pkt[DNS].ancount):
                dns_responses.append(pkt[DNSRR][x].rdata)
            src = pkt[IP].src
            dst = pkt[DNSQR].qname
            if (src not in nodes_dns_comms):
                nodes_dns_comms[src] = []
            #bc we want to keep track of domains if used dns
            if (dst not in nodes_dns_comms and dst not in dns_responses):
                nodes_dns_comms[src].append(dst)

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if (src not in nodes_ip_comms):
                nodes_ip_comms[src] = []
            if (dst not in nodes_ip_comms[src]):
                nodes_ip_comms[src].append(dst)

    print(nodes_ip_comms)
    print(nodes_dns_comms)
    return nodes_ip_comms, nodes_dns_comms
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapfile", help="pcap file for traffic")
    
    args = parser.parse_args()
    packets = rdpcap(args.pcapfile)
    
    get_endpoint_comms(packets)