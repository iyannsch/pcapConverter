import sys
import os
import pyshark
import json
from iputils import IPUtils
import socket

usage = """usage: ./main.py [path to .pcap file] [duration in seconds] [path to .json database file]"""

# Here you can define the devices you expect to find traces from
ip_name_dict = {
    'localhost': [
        '192.168.0.1',
        '127.0.0.1'
    ],
    'next_device': [
        'all',
        'of',
        'the',
        'IPv4',
        'and'
        'IPv6',
        'addresses'
    ],
    'laptop': [
        '192.168.5.185',
    ]
}

def get_device_of_packet(src, dst):
    for key, val in ip_name_dict.items():
        if src in val:
            return key
        if dst in val:
            return key
    return 'unknown'

# Return 0 if incoming, 1 if outgoing, and 2 if internal
def check_in_out_internal(src, dst):
    return 0

class MasterStamp:
    def __init__(self):
        self.timestamp = ""     # ISO 8601 Timestamp of start of stamp
        self.duration = 0       # Duration of stamp in seconds
        self.devices = {}       # Dictionary of Device Stamps
        self.http_using = []    # Array of services that use HTTP TODO

class DeviceStamp:
    def __init__(self):
        self.total_count = 0                # Total amount of packages generally
        self.total_size = 0                 # Total size of packages generally

        self.total_out_ipv4_count = 0       # Total amount of outgoing packages TODO
        self.total_in_ipv4_count = 0        # Total amount of incoming packages TODO
        self.total_out_ipv6_count = 0       # Total amount of outgoing packages TODO
        self.total_in_ipv6_count = 0        # Total amount of incoming packages TODO
        self.total_out_ipv4_size = 0        # Total size of outgoing packages in bytes TODO
        self.total_in_ipv4_size = 0         # Total size of incoming packages in bytes TODO
        self.total_out_ipv6_size = 0        # Total size of outgoing packages in bytes TODO
        self.total_in_ipv6_size = 0         # Total size of incoming packages in bytes TODO

        self.total_internal_ipv4_count = 0  # Total amount of intenral packages TODO
        self.total_internal_ipv4_size = 0   # Total size of internal packages in bytes TODO
        self.total_internal_ipv6_count = 0  # Total amount of intenral packages TODO
        self.total_internal_ipv6_size = 0   # Total size of internal packages in bytes TODO

        self.total_enc_count = 0      # Total amount of encrypted packages TODO
        self.total_enc_size = 0      # Total size of encrypted packages in bytes TODO

        self.proto = {}         # Count dictionary for protocols
        self.dns = []           # Array of queried domains
        self.enc_type = {}      # Count dictionary for encryption types TODO

        self.services_ipv4 = {"Google": 0, "AWS": 0, "Azure": 0}      # Dictionary of services-traffic size in bytes in ipv4 TODO
        self.services_ipv6 = {"Google": 0, "AWS": 0, "Azure": 0}      # Dictionary of services-traffic size in bytes in ipv6 TODO

def main():
    if(not len(sys.argv) == 4):
        print(usage)
        exit(1)
    file_name = sys.argv[1]
    duration = int(sys.argv[2])
    output_file = sys.argv[3]

    #################################
    # Parsing Capture Data          #
    #################################

    cap = pyshark.FileCapture(file_name)

    mstamp = MasterStamp()
    ipu = IPUtils()

    timestamp = file_name[4:-5]
    mstamp.timestamp = timestamp
    mstamp.duration = duration

    for c in cap:
        if(len(c.layers) < 3):
            continue

        if(c.layers[1].version.show == "4"):
            dev_name = get_device_of_packet(c.ip.src, c.ip.dst)
            traffic_type = check_in_out_internal(c.ip.src, c.ip.dst)
        elif(c.layers[1].version.show == "6"):
            dev_name = get_device_of_packet(c.ipv6.src, c.ipv6.dst)
            traffic_type = check_in_out_internal(c.ipv6.src, c.ipv6.dst)
        else:
            continue # We ignore all non-ipv4 or ipv6 packages

        if(not (dev_name in mstamp.devices)):
            mstamp.devices[dev_name] = DeviceStamp()

        mstamp.devices[dev_name].total_count += 1
        pack_len = int(c.length) # Length of Ethernet Frame in bytes
        mstamp.devices[dev_name].total_size += pack_len
        if(c.layers[1].version.show == "4"):
            if(traffic_type == 0):
                mstamp.devices[dev_name].total_in_ipv4_count += 1
                mstamp.devices[dev_name].total_in_ipv4_size += pack_len
            elif(traffic_type == 1):
                mstamp.devices[dev_name].total_out_ipv4_count += 1
                mstamp.devices[dev_name].total_out_ipv4_size += pack_len
            elif(traffic_type == 2):
                mstamp.devices[dev_name].total_internal_ipv4_count += 1
                mstamp.devices[dev_name].total_internal_ipv4_size += pack_len

            # Check IPs for cloud service providers using IPv4
            if(ipu.check_Google(c.ip.src, True) or ipu.check_Google(c.ip.dst, True)):
                # This is a Google Cloud related packet
                mstamp.devices[dev_name].services_ipv4["Google"] += pack_len
            elif(ipu.check_AWS(c.ip.src, True) or ipu.check_AWS(c.ip.dst, True)):
                # This is an AWS related packet
                mstamp.devices[dev_name].services_ipv4["AWS"] += pack_len
            elif(ipu.check_Azure(c.ip.src, True) or ipu.check_Azure(c.ip.dst, True)):
                # This is an Azure related packet
                mstamp.devices[dev_name].services_ipv4["Azure"] += pack_len

            proto_name = c.layers[1].proto.showname_value.split(" ")[0]

        elif(c.layers[1].version.show == "6"):
            if(traffic_type == 0):
                mstamp.devices[dev_name].total_in_ipv6_count += 1
                mstamp.devices[dev_name].total_in_ipv6_size += pack_len
            elif(traffic_type == 1):
                mstamp.devices[dev_name].total_out_ipv6_count += 1
                mstamp.devices[dev_name].total_out_ipv6_size += pack_len
            elif(traffic_type == 2):
                mstamp.devices[dev_name].total_internal_ipv6_count += 1
                mstamp.devices[dev_name].total_internal_ipv6_size += pack_len

            # Check IPs for cloud service providers using IPv6
            if(ipu.check_Google(c.ipv6.src, False) or ipu.check_Google(c.ipv6.dst, False)):
                # This is a Google Cloud related packet
                mstamp.devices[dev_name].services_ipv6["Google"] += pack_len
            elif(ipu.check_AWS(c.ipv6.src, False) or ipu.check_AWS(c.ipv6.dst, False)):
                # This is an AWS related packet
                mstamp.devices[dev_name].services_ipv6["AWS"] += pack_len
            elif(ipu.check_Azure(c.ipv6.src, False) or ipu.check_Azure(c.ipv6.dst, False)):
                # This is an Azure related packet
                mstamp.devices[dev_name].services_ipv6["Azure"] += pack_len
            
            proto_name = c.layers[1].nxt.showname_value.split(" ")[0]

        if(proto_name in mstamp.devices[dev_name].proto):
            mstamp.devices[dev_name].proto[proto_name] += 1
        else:
            mstamp.devices[dev_name].proto[proto_name] = 1

        # Check if this is a DNS packet
        if("DNS" in c):
            dns_name = c.dns.qry_name
            if(not dns_name in mstamp.devices[dev_name].dns):
                mstamp.devices[dev_name].dns.append(dns_name)

        # Check if this is a HTTP packet
        if("HTTP" in c):
            # Unencrypted traffic that we want to log the service of
            in_out = check_in_out_internal(c.ip.src, c.ip.dst)
            service_ip = ""
            if(in_out == 0):
                # incoming traffic: service-ip = src
                service_ip = c.ip.src
            elif(in_out == 1):
                # outgoing traffic: service-ip = dst
                service_ip = c.ip.dst
            
            if(service_ip != ""):
                #try reverse dns
                try:
                    domain = socket.gethostbyaddr(service_ip)[0]
                except socket.herror:
                    domain = service_ip
                if(not domain in mstamp.http_using):
                    mstamp.http_using.append(domain)


    ###################################
    # Serialize and Append to JSON db #
    ###################################

    if(not os.path.exists(output_file)):
        db = []
    else:
        with open(output_file, "r") as fh:
            db = json.load(fh)

    db.append(mstamp)

    with open(output_file, "w+") as fh:
        json.dump(
                db, 
                fh, 
                default=lambda o:o.__dict__,
                indent=2
                )

    print("Current DB:")
    print(json.dumps(
                db, 
                default=lambda o:o.__dict__,
                indent=2
                ))

    ########################
    # Delete Original File #
    ########################

    # TODO

if __name__ == "__main__":
    main()
