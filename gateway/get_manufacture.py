import json
from datetime import datetime
from db_config import mongo_ops
import whois
from utils import query_oui

domaindict = {}
cnt = 5
resultdomain = ''
who = {}
result = "no manufacturer"

devices = mongo_ops.query_devices()
for device in devices:
    resultdomain = ''
    domaindict = {}
    who = {}
    result = ""
    
    print device['mac_address']
    endpts = mongo_ops.get_device_endpoints(device)
    domains = mongo_ops.get_device_domains(device)
    #Manufacturer = mongo_ops.get_device_manufacturer(device)
    for endpt in endpts:
            tempip = endpt["ip"]
            if "192.168" in tempip:
                    continue
            for domain in domains:
                    for ip in domain["ips"]:
                            if tempip == ip:
                                host_name = domain["domain"]
                                host = host_name.split('.')
                                host_name = host[len(host)-3] + '.' + host[len(host)-2]
                                if host_name in domaindict:
                                    domaindict[host_name] = domaindict[host_name] + 1
                                else:
                                    
                                    domaindict[host_name] = 1                                        
    for domain in domaindict:
        if domaindict[domain] > cnt:
            cnt = domaindict[domain]
            resultdomain = domain
    print resultdomain
    while cnt > 0:      
        try:
            temp = whois.whois(resultdomain)["org"]
        except:
            print "time out"
        if temp in who:
            who[temp] = who[temp] + 1
        else:
            who[temp] = 1 
        cnt = cnt - 1
        
    for wh in who:
        if wh:
            result = str(wh)
    print "result of manufacturer by whois is: " + result
        

    mac_address = mongo_ops.get_mac_address(device)
    manuf2 = query_oui(mac_address)
    print "result of manufacturer by mac address is: " + manuf2

    
                                
