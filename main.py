import sys
import os
import pyshark

usage = """usage: ./main.py [.pcap file] [duration] [.json database file]"""

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

    stamp = Stamp()

    for c in cap:
        stamp.total += 1
        if(c.layers[1].version.show == "4"):
            stamp.total_ipv4 += 1
        elif(c.layers[1].version.show == "6"):
            stamp.total_ipv6 += 1

    # TODO Serialize / Append this stamp object
    print("Pkg count", pkg_count)
    print("Pkg count ip4", pkg_count_ipv4)
    print("Pkg count ip6", pkg_count_ipv6)

if __name__ == "__main__":
    main()
