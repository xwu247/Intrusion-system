from scapy.all import *
import argparse
import json
import numpy as np

def get_endpoint_comms(pkts):
    ip_packet_count = 0
    
    nodes_ip_comms = dict()
    nodes_dns_comms = dict()
    dns_responses = dict()

    endpoint_pkt_sizes = dict()
    for pkt in pkts:
        if DNS in pkt and ('Ans' in pkt.summary()):
            src = pkt[IP].dst  #because this is the answer to a query
            dst = pkt[DNSQR].qname
            responses = []
            for x in range(pkt[DNS].ancount):
                responses.append(pkt[DNSRR][x].rdata)
            dns_responses[dst] = responses
            
            if (src not in nodes_dns_comms):
                nodes_dns_comms[src] = dict()
                nodes_dns_comms[src]['endpoints'] = dict()

                if (src not in endpoint_pkt_sizes):
                    endpoint_pkt_sizes[src] = dict()
                
            if (dst not in nodes_dns_comms[src]['endpoints']):
                features_dict = dict()
                nodes_dns_comms[src]['endpoints'][dst] = features_dict

        elif IP in pkt:
            ip_packet_count += 1
            src = pkt[IP].src
            dst = pkt[IP].dst
            if (src not in nodes_ip_comms):
                dns = False
                for x in dns_responses:
                    if (dst in dns_responses[x]):
                        dns = True
                        break
                if (not dns):
                    nodes_ip_comms[src] = dict()
                    nodes_ip_comms[src]['endpoints'] = dict()

                    if (src not in endpoint_pkt_sizes):
                        endpoint_pkt_sizes[src] = dict()

            if (dst not in nodes_ip_comms[src]['endpoints']):
                #bc we want to keep track of domains if used dns
                dns = False
                for x in dns_responses:
                    if (dst in dns_responses[x]):
                        dns = True
                        break
                if (not dns):
                    features_dict = dict()
                    nodes_ip_comms[src]['endpoints'][dst] = features_dict


            #now need to associate packet sizes with correct src, dest pair and put in list
            dns = False
            for x in dns_responses:
                if (dst in dns_responses[x]):
                    if x not in endpoint_pkt_sizes[src]:
                        endpoint_pkt_sizes[src][x] = []
                    endpoint_pkt_sizes[src][x].append(len(pkt))
                    dns = True
                    break
            if (not dns):
                if dst not in endpoint_pkt_sizes[src]:
                    endpoint_pkt_sizes[src][dst] = []
                    endpoint_pkt_sizes[src][dst].append(len(pkt))
                else :
                    endpoint_pkt_sizes[src][dst].append(len(pkt))


    print('ip packet count: ' + str(ip_packet_count))
                
    print('\ndns_responses:\n')
    for x in dns_responses:
        print(x, dns_responses[x])
    print('\n----------------------------------\n')


    for src in endpoint_pkt_sizes:
        for dst in endpoint_pkt_sizes[src]:
            lens = np.array(endpoint_pkt_sizes[src][dst])
            if src in nodes_dns_comms and dst in nodes_dns_comms[src]['endpoints']:
                nodes_dns_comms[src]['endpoints'][dst]['mean_packet_size'] = np.mean(lens)
                nodes_dns_comms[src]['endpoints'][dst]['std_dev_packet_size'] = np.std(lens)
                nodes_dns_comms[src]['endpoints'][dst]['min_packet_size'] = np.min(lens)
                nodes_dns_comms[src]['endpoints'][dst]['max_packet_size'] = np.max(lens)
                nodes_dns_comms[src]['endpoints'][dst]['median_packet_size'] = np.median(lens)
            else:
                nodes_ip_comms[src]['endpoints'][dst]['mean_packet_size'] = np.mean(lens)
                nodes_ip_comms[src]['endpoints'][dst]['std_dev_packet_size'] = np.std(lens)
                nodes_ip_comms[src]['endpoints'][dst]['min_packet_size'] = np.min(lens)
                nodes_ip_comms[src]['endpoints'][dst]['max_packet_size'] = np.max(lens)
                nodes_ip_comms[src]['endpoints'][dst]['median_packet_size'] = np.median(lens)

    print('ip endpoints:')
    for src in nodes_ip_comms:
        print('src = ' + src)
        for dst in nodes_ip_comms[src]['endpoints']:
            print('\t' + dst + ' mean packet size = ' + str(nodes_ip_comms[src]['endpoints'][dst]['mean_packet_size']))
            print('\t' + dst + ' median packet size = ' + str(nodes_ip_comms[src]['endpoints'][dst]['median_packet_size']))
            print('\t' + dst + ' std_dev packet size = ' + str(nodes_ip_comms[src]['endpoints'][dst]['std_dev_packet_size']))
            print('\t' + dst + ' min packet size = ' + str(nodes_ip_comms[src]['endpoints'][dst]['min_packet_size']))
            print('\t' + dst + ' max packet size = ' + str(nodes_ip_comms[src]['endpoints'][dst]['max_packet_size']))
            print('')
    print('\n------------------------------------\n')
    print('dns endpoints')
    for src in nodes_dns_comms:
        print('src = ' + src)
        for dst in nodes_dns_comms[src]['endpoints']:
            print('\t' + dst + ' mean packet size = ' + str(nodes_dns_comms[src]['endpoints'][dst]['mean_packet_size']))
            print('\t' + dst + ' median packet size = ' + str(nodes_dns_comms[src]['endpoints'][dst]['median_packet_size']))
            print('\t' + dst + ' std_dev packet size = ' + str(nodes_dns_comms[src]['endpoints'][dst]['std_dev_packet_size']))
            print('\t' + dst + ' min packet size = ' + str(nodes_dns_comms[src]['endpoints'][dst]['min_packet_size']))
            print('\t' + dst + ' max packet size = ' + str(nodes_dns_comms[src]['endpoints'][dst]['max_packet_size']))
            print('')
    print('\n--------------------------------------\n')
    #print('packet sizes')
    #print(endpoint_pkt_sizes)
    #return nodes_ip_comms, nodes_dns_comms
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapfile", help="pcap file for traffic")
    
    args = parser.parse_args()
    print('parsing pcap file...')
    packets = rdpcap(args.pcapfile)
    print('pcap parsed')
    
    get_endpoint_comms(packets)
