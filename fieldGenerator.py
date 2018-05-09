import json
from datetime import datetime
from db_config import mongo_ops

def aceto_localgenerator(**to):
    name = "iot-todev"
    locname = "lociot-todev"
    if to["protocol"] == 17:
        ace = {
                      "name": locname,
                      "match": {
                                "ietf-mud:mud":{
                                    "local-network":[
                                        "null"
                                        ]
                                },
				"ipv4":{
					"protocol": to["protocol"] 
					},
				"udp":{	
					"sport": to["sport"],
					"dport": to["dport"]
				},
                            	"actions":{
                                	"forwarding": "accept"
                            	}
                            }
                    }
    elif to["protocol"] == 1:
        ace = {
                      "name": locname,
                      "match": {
                                "ietf-mud:mud":{
                                    "local-network":[
                                        "null"
                                        ]
                                },
				"ipv4":{
					"protocol": to["protocol"] 
					},
				"icmp":{	

				},
                            	"actions":{
                                	"forwarding": "accept"
                            	}
                            }
                    }
    elif:
        ace = {
                          "name": locname,
                          "match": {
                                    "ietf-mud:mud":{
                                        "local-network":[
                                            "null"
                                            ]
                                    },
                                    "ipv4":{
                                            "protocol": to["protocol"] 
                                            },
                                    "tcp":{	
                                            "sport": to["sport"],
                                            "dport": to["dport"]
                                    },
                                    "actions":{
                                            "forwarding": "accept"
                                    }
                                }
                        }
                   
    return ace

def acetogenerator(**to):
    name = "iot-todev"
    locname = "lociot-todev"
    if to["protocol"] == 17:
        ace = {
                      "name": name,
                      "match": {
				"ipv4":{
					"host_name": to["host_name"],
					"protocol": to["protocol"] 
					},
				"udp":{	
					"sport": to["sport"],
					"dport": to["dport"]
				},
                            	"actions":{
                                	"forwarding": "accept"
                            	}
                            }
                    }
    else:
        ace = {
                          "name": name,
                          "match": {
                                    "ipv4":{
                                            "host_name": to["host_name"],
                                            "protocol": to["protocol"] 
                                            },
                                    "tcp":{	
                                            "sport": to["sport"],
                                            "dport": to["dport"]
                                    },
                                    "actions":{
                                            "forwarding": "accept"
                                    }
                                }
                        }
                   
    return ace

def acefr_localgenerator(**fr):
    name = "iot-frdev"
    locname = "lociot-frdev"
    if fr["protocol"] == 17:
        ace = {
                      "name": locname,
                      "match": {
                                "ietf-mud:mud":{
                                    "local-network":[
                                        "null"
                                        ]
                                },
				"ipv4":{
					"protocol": fr["protocol"] 
					},
				"udp":{	
					"sport": fr["sport"],
					"dport": fr["dport"]
				},
                            	"actions":{
                                	"forwarding": "accept"
                            	}
                            }
                    }
    elif fr["protocol"] == 1:
        ace = {
                      "name": locname,
                      "match": {
                                "ietf-mud:mud":{
                                    "local-network":[
                                        "null"
                                        ]
                                },
				"ipv4":{
					"protocol": fr["protocol"] 
					},
				"icmp":{	

				},
                            	"actions":{
                                	"forwarding": "accept"
                            	}
                            }
                    }
    else:
        ace = {
                          "name": locname,
                          "match": {
                                    "ietf-mud:mud":{
                                        "local-network":[
                                            "null"
                                            ]
                                    },
                                    "ipv4":{
                                            "protocol": fr["protocol"] 
                                            },
                                    "tcp":{	
                                            "sport": fr["sport"],
                                            "dport": fr["dport"]
                                    },
                                    "actions":{
                                            "forwarding": "accept"
                                    }
                                }
                        }
                   
    return ace

def acefrgenerator(**fr):
    name = "iot-frdev"
    locname = "lociot-frdev"
    if fr["protocol"] == 17:
        ace = {
                      "name": name,
                      "match": {
				"ipv4":{
					"host_name": fr["host_name"],
					"protocol": fr["protocol"] 
					},
				"udp":{	
					"sport": fr["sport"],
					"dport": fr["dport"]
				},
                            	"actions":{
                                	"forwarding": "accept"
                            	}
                            }
                    }
    else:
        ace = {
                          "name": name,
                          "match": {
                                    "ipv4":{
                                            "host_name": fr["host_name"],
                                            "protocol": fr["protocol"] 
                                            },
                                    "tcp":{	
                                            "sport": fr["sport"],
                                            "dport": fr["dport"]
                                    },
                                    "actions":{
                                            "forwarding": "accept"
                                    }
                                }
                        }
                   
    return ace


def aclgenerator(ace):
    toname = "mud-36750-v4to"
    frname = "mud-36750-v4fr"
    ACL = {
            "name": "mud-36750-v4to",
            "type": "ipv4-acl-type",
            "aces": ace
          },
    {
            "name": "mud-36750-v4fr",
            "type": "ipv4-acl-type",
            "aces": ace
            }
    return ACL



'''endpts = [{ "ip" : "224.0.0.251", "fr" : [ 
												{ "dport" : 5353, "sport" : 5353, "protocol" : 17 } 
											], 
									"to" : [ ] 
			}, 
			{ "ip" : "52.44.92.194", "fr" : [ 
												{ "dport" : 8555, "sport" : 35746, "protocol" : 6 }, 
												{ "dport" : 8555, "sport" : 35749, "protocol" : 6 } 
											], 
									"to" : [ 
												{ "dport" : 35746, "sport" : 8555, "protocol" : 6 }, 
												{ "dport" : 35749, "sport" : 8555, "protocol" : 6 } 
											] 
			}, 
			{ "ip" : "239.255.255.250", "fr" : [ 
												{ "dport" : 1900, "sport" : 51772, "protocol" : 17 } 
											], 
										"to" : [ ] 
			}, 
			{ "ip" : "52.22.50.150", "fr" : [ 
												{ "dport" : 6800, "sport" : 52568, "protocol" : 6 }, 
												{ "dport" : 6900, "sport" : 42023, "protocol" : 6 }, 
												{ "dport" : 6800, "sport" : 52571, "protocol" : 6 }, 
												{ "dport" : 6900, "sport" : 42026, "protocol" : 6 } ], 
									"to" : [ 
												{ "dport" : 52568, "sport" : 6800, "protocol" : 6 }, 
												{ "dport" : 42023, "sport" : 6900, "protocol" : 6 }, 
												{ "dport" : 52571, "sport" : 6800, "protocol" : 6 }, 
												{ "dport" : 42026, "sport" : 6900, "protocol" : 6 } 
											] 
			}, 
			{ "ip" : "138.236.128.36", "fr" : [ 
												{ "dport" : 123, "sport" : 36592, "protocol" : 17 } 
											], 
										"to" : [ 
												{ "dport" : 36592, "sport" : 123, "protocol" : 17 } 
											] 
			}, 
			{ "ip" : "192.168.1.1", "fr" : [ 
												{ "dport" : -1, "sport" : -1, "protocol" : 1 } 
											], 
									"to" : [ 
												{ "dport" : -1, "sport" : -1, "protocol" : 1 } 
											] 
			} ]
domains = [ 
		{ "ips" : [ "tdev.ezviz7.com.", "lbs-726140220.us-east-1.elb.amazonaws.com.", "54.164.184.247", "52.44.92.194" ], "domain" : "dev.ezviz7.com." }, 
		{ "ips" : [ "alarmadapter-512731437.us-east-1.elb.amazonaws.com.", "52.21.175.180", "52.86.169.50" ], "domain" : "alarmus.ezvizlife.com." }, 
		{ "ips" : [ "lbs-726140220.us-east-1.elb.amazonaws.com.", "52.44.92.194", "54.164.184.247" ], "domain" : "dev.us.ezviz7.com." }, 
		{ "ips" : [ "138.236.128.36", "129.6.15.28", "162.210.111.4", "198.50.238.156" ], "domain" : "0.amazon.pool.ntp.org." } 
	]'''
cnt = 0
devices = mongo_ops.query_devices()
for device in devices:
    endpts = mongo_ops.get_device_endpoints(device)
    domains = mongo_ops.get_device_domains(device)
    Manufacturer = mongo_ops.get_device_manufacturer(device)
    host_name = ""
        
    acefr = list()
    for endpt in endpts:
            tempip = endpt["ip"]
            if "192.168" in tempip:
                    tempfr = endpt["fr"]
                    for temp in tempfr:
                            fr = {"dport" : temp["dport"], "sport" : temp["sport"], "protocol" : temp["protocol"]}
                            acefr.append(acefr_localgenerator(**fr))
                            
    for endpt in endpts:
            tempip = endpt["ip"]
            if "192.168" in tempip:
                    break
            for domain in domains:
                    for ip in domain["ips"]:
                            if tempip == ip:
                                    host_name = domain["domain"]
                                    tempfr = endpt["fr"]
                                    for temp in tempfr:
                                            fr = {"dport" : temp["dport"], "sport" : temp["sport"], "protocol" : temp["protocol"], "host_name": host_name}
                                            acefr.append(acefrgenerator(**fr))
    #print acefr

    aceto = list()
    for endpt in endpts:
            tempip = endpt["ip"]
            if "192.168" in tempip:
                    tempto = endpt["to"]
                    for temp in tempto:
                            to = {"dport" : temp["dport"], "sport" : temp["sport"], "protocol" : temp["protocol"]}
                            aceto.append(aceto_localgenerator(**to))


    for endpt in endpts:
            tempip = endpt["ip"]
            if "192.168" in tempip:
                    break
            for domain in domains:
                    for ip in domain["ips"]:
                            if tempip == ip:
                                    host_name = domain["domain"]
                                    tempto = endpt["to"]
                                    for temp in tempto:
                                            to = {"dport" : temp["dport"], "sport" : temp["sport"], "protocol" : temp["protocol"], "host_name": host_name}
                                            aceto.append(acetogenerator(**to))
                    
    #print aceto

    ACL = [{
                            "name": "mud-36750-v4to",
                            "type": "ipv4-acl-type",
                            "aces": aceto
                      },
            {
                            "name": "mud-36750-v4fr",
                            "type": "ipv4-acl-type",
                            "aces": acefr
                            }]
    #print ACL


    filename = 'data' + str(cnt) +'.json'
    cnt = cnt + 1
    url = ""
    update = str(datetime.now())
    validity = 48
    issupported = True
    systeminfo = "This is used in Dynamic Profiling"
    mud = {
              "ietf-mud:mud": {
                    "mud-url": url,
                    "last-update": update,
                    "cache-validity": validity,
                    "is-supported": issupported,
                    "systeminfo": systeminfo,
                    "Manufacturer": "123",
                    "from-device-policy": {
                      "access-lists": {
                            "access-list": [
                                            {
                                                    "acl-name": "ACL-36750-v4fr",
                                                    "acl-type": ""
                                            }
                                    ]
                       }
                     },
                    "to-device-policy": {
                      "access-lists": {
                            "access-list": [
                                            {
                                                    "acl-name": "ACL-36750-v4to",
                                                    "acl-type":""
                                            }
                                    ]
                      }
                    }
              },
              "ietf-access-control-list:access-lists": {
                    "acl": ACL
                    }
            }
    print mud
    with open(filename, 'w') as outfile:  
            json.dump(mud, outfile, indent = 4, ensure_ascii = False)
    #jsongenerator("AmpakTec", match)

