import sys
import os
import pyshark

usage = """usage: ./main.py [.pcap file] [duration] [.json database file]"""

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
    ]
}

# "Frame" (15 minutes of traffic)
# 
# - #Total L4 Packages
# - #Total L4 Packages encrypted
# - protocols {
#             "udp": #L4 Packages,
#             "tcp": #L4 Packages,
#             ...    
#         }
# - dns ["ocs.apple.com", "abc.google.com", ...]
# - encryption types {
#             "TLS 1.1": #L4 Packages
#             "TLS 1.3": #L4 Packages    
#             }


# Stamp 1
# - timestamp
# - duration
# - devices:
#   - laptop1:
#      - total
#      - total_ipv4
#      - ...

class MasterStamp:
    def __init__(self):
        self.timestamp = ""     # ISO 8601 Timestamp of start of stamp
        self.duration = 0       # Duration of stamp in seconds
        self.devices = {}       # Dictionary of Device Stamps


class DeviceStamp:
    def __init__(self):
        self.total = 0          # Total amount of L4 packages
        self.total_ipv4 = 0     # Total amount of L4 packages
        self.total_ipv6 = 0     # Total amount of L4 packages
        self.total_enc = 0      # Total amount of encrypted packages
        self.proto = {}         # Count dictionary for protocols
        self.dns = []           # Array of queried domains
        self.enc_type = {}      # Count dictionary for encryption types


def main():
    if(len(sys.argv) == 3):
        print(usage)
        exit(1)
    file_name = sys.argv[1]
    print("Parsing", file_name)

    cap = pyshark.FileCapture(file_name)

    mstamp = MasterStamp()

    for c in cap:
        dev_name = get_device_of_packet(c.ip.src, c.ip.dst)
        if(not (dev_name in mstamp.devices)):
            mstamp.devices[dev_name] = DeviceStamp()

        mstamp.devices[dev_name] += 1
        if(c.layers[1].version.show == "4"):
            mstamp.devices[dev_name].total_ipv4 += 1
        elif(c.layers[1].version.show == "6"):
            mstamp.devices[dev_name].total_ipv6 += 1
        proto_name = c.layers[1].proto.showname_value.split(" ")[0]
        if(proto_name in mstamp.devices[dev_name].proto):
            mstamp.devices[dev_name].proto[proto_name] += 1
        else:
            mstamp.devices[dev_name].proto[proto_name] = 1

    # TODO Serialize / Append this stamp object
    # print("Pkg count", stamp.total)
    # print("Pkg count ip4", stamp.total_ipv4)
    # print("Pkg count ip6", stamp.total_ipv6)

if __name__ == "__main__":
    main()


def get_device_of_packet(src, dst):
    for key, val in ip_name_dict.items():
        if src in val:
            return key
        if dst in val:
            return key
    return 'unknown'
