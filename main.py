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

class Stamp:
    def __init__(self):
        self.total = 0          # Total amount of L4 packages
        self.total_ipv4 = 0     # Total amount of L4 packages
        self.total_ipv6 = 0     # Total amount of L4 packages
        self.total_enc = 0      # Total amount of encrypted packages
        self.timestamp = ""     # ISO 8601 Timestamp of start of stamp
        self.duration = 0       # Duration of stamp in seconds
        self.proto = {}         # Count dictionary for protocols
        self.dns = []           # Array of queried domains
        self.enc_type = {}      # Count dictionary for encryption types

l4_proto = [""]

def main():
    if(len(sys.argv) == 3):
        print(usage)
        exit(1)
    file_name = sys.argv[1]
    print("Parsing", file_name)

    cap = pyshark.FileCapture(file_name)

    pkg_count = 0
    pkg_count_ipv4 = 0
    pkg_count_ipv6 = 0
    pkg_count_enc = 0

    for c in cap:
        pkg_count += 1

        if(c.layers[1].version == 4):
            pkg_count_ipv4 += 1
        elif(c.layers[1].version == 6):
            pkg_count_ipv6 += 1
        #print(c.layers)
        exit()
    #print(count)
    print("Pkg count", pkg_count)
    print("Pkg count ip4", pkg_count_ipv4)
    print("Pkg count ip6", pkg_count_ipv6)

    stamp = Stamp()
    stamp.total = pkg_count
    stamp.total_ipv4 = pkg_count_ipv4
    stamp.total_ipv6 = pkg_count_ipv6

if __name__ == "__main__":
    main()


def get_ip_name(ip):
    for key, val in ip_name_dict.items():
        if ip in val:
            return key
    return 'unknown'