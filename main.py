import sys
import os
import pyshark
import json
from iputils import IPUtils

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

class MasterStamp:
    def __init__(self):
        self.timestamp = ""     # ISO 8601 Timestamp of start of stamp
        self.duration = 0       # Duration of stamp in seconds
        self.devices = {}       # Dictionary of Device Stamps
        self.http_using = []    # Array of services that use HTTP TODO

class DeviceStamp:
    def __init__(self):
        self.total_out_ipv4_count = 0       # Total amount of outgoing L4 packages TODO
        self.total_in_ipv4_count = 0        # Total amount of incoming L4 packages TODO
        self.total_out_ipv6_count = 0       # Total amount of outgoing L4 packages TODO
        self.total_in_ipv6_count = 0        # Total amount of incoming L4 packages TODO
        self.total_out_ipv4_size = 0        # Total size of outgoing L4 packages in bytes TODO
        self.total_in_ipv4_size = 0         # Total size of incoming L4 packages in bytes TODO
        self.total_out_ipv6_size = 0        # Total size of outgoing L4 packages in bytes TODO
        self.total_in_ipv6_size = 0         # Total size of incoming L4 packages in bytes TODO

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
        dev_name = get_device_of_packet(c.ip.src, c.ip.dst)
        if(not (dev_name in mstamp.devices)):
            mstamp.devices[dev_name] = DeviceStamp()

        mstamp.devices[dev_name].total += 1
        if(c.layers[1].version.show == "4"):
            mstamp.devices[dev_name].total_ipv4 += 1

            # Check IPs for cloud service providers using IPv4
            if(ipu.check_Google(c.ip.src, True) or ipu.check_Google(c.ip.dst, True)):
                # This is a Google Cloud related packet
                mstamp.devices[dev_name].services_ipv4["Google"] += c.length
            elif(ipu.check_AWS(c.ip.src, True) or ipu.check_AWS(c.ip.dst, True)):
                # This is an AWS related packet
                mstamp.devices[dev_name].services_ipv4["AWS"] += c.length
            elif(ipu.check_Azure(c.ip.src, True) or ipu.check_Azure(c.ip.dst, True)):
                # This is an Azure related packet
                mstamp.devices[dev_name].services_ipv4["Azure"] += c.length

        elif(c.layers[1].version.show == "6"):
            mstamp.devices[dev_name].total_ipv6 += 1

            # Check IPs for cloud service providers using IPv6
            if(ipu.check_Google(c.ip.src, False) or ipu.check_Google(c.ip.dst, False)):
                # This is a Google Cloud related packet
                mstamp.devices[dev_name].services_ipv6["Google"] += c.length
            elif(ipu.check_AWS(c.ip.src, False) or ipu.check_AWS(c.ip.dst, False)):
                # This is an AWS related packet
                mstamp.devices[dev_name].services_ipv6["AWS"] += c.length
            elif(ipu.check_Azure(c.ip.src, False) or ipu.check_Azure(c.ip.dst, False)):
                # This is an Azure related packet
                mstamp.devices[dev_name].services_ipv6["Azure"] += c.length

        proto_name = c.layers[1].proto.showname_value.split(" ")[0]

        if(proto_name in mstamp.devices[dev_name].proto):
            mstamp.devices[dev_name].proto[proto_name] += 1
        else:
            mstamp.devices[dev_name].proto[proto_name] = 1

        if("DNS" in c):
            dns_name = c.dns.qry_name
            if(not dns_name in mstamp.devices[dev_name].dns):
                mstamp.devices[dev_name].dns.append(dns_name)


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
