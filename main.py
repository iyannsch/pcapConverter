import sys
import os
import pyshark
import json
from iputils import IPUtils
import ipaddress
import netifaces
from netifaces import AF_INET, AF_INET6
import socket
from devconfig import ip_name_dict

usage = """usage: ./main.py [path to .pcap file] [duration in seconds] [path to .json database file]"""

def get_device_of_packet(src, dst):
    for key, val in ip_name_dict.items():
        if src in val:
            return key
        if dst in val:
            return key
    return 'unknown'

def format_ip(a):
    addr = ipaddress.ip_address(a["addr"])
    backup = "255.255.255.0" if (addr.version == 4) else "ffff:ffff:ffff:ffff::"
    netmask = ipaddress.ip_interface(a.setdefault("netmask", backup)).ip
    cnt = 0
    for b in netmask.packed:
        bcnt = 0
        bt = b
        for _ in range(8):
            bcnt += bt & 0x01
            bt >>= 1
        cnt += bcnt
    return addr.compressed + "/" + str(cnt)

# Return 0 if incoming, 1 if outgoing, and 2 if internal
def check_in_out_internal(src, dst, ip_netws):
    ipsrc = ipaddress.ip_address(src)
    ipdst = ipaddress.ip_address(dst)

    src_in_net = False
    for netw in ip_netws:
        src_in_net |= ipsrc in netw

    dst_in_net = False
    for netw in ip_netws:
        dst_in_net |= ipdst in netw

    if(src_in_net and (not dst_in_net)):
        return 0
    elif((not src_in_net) and dst_in_net):
        return 1
    else:
        return 2 # Assuming this is internal traffic

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

        self.proto = {}         # Size dictionary for protocols in bytes
        self.dns = []           # Array of queried domains
        self.enc_type = {}      # Count dictionary for encryption types TODO

        self.services_ipv4 = {"Google": 0, "AWS": 0, "Azure": 0}      # Dictionary of services-traffic size in bytes in ipv4 TODO
        self.services_ipv6 = {"Google": 0, "AWS": 0, "Azure": 0}      # Dictionary of services-traffic size in bytes in ipv6 TODO

def main():

    #########
    # Setup #
    #########

    if(not len(sys.argv) == 5):
        print(usage)
        exit(1)
    file_name = sys.argv[1]
    output_file = sys.argv[2]

    duration = int(sys.argv[3])
    interface = sys.argv[4]

    # The following is a hack because the addresses of netifaces are not the correct
    # format that ipaddress.ip_network uses
    ipv4addrs = netifaces.ifaddresses(interface)[AF_INET]
    ipv6addrs = netifaces.ifaddresses(interface)[AF_INET6]
    ipv4addr_formatted = [format_ip(a)  for a in ipv4addrs]
    ipv6addr_formatted = [format_ip(a)  for a in ipv6addrs]
    ipv4_netws = [ipaddress.ip_network(ip, strict=False) for ip in ipv4addr_formatted]
    ipv6_netws = [ipaddress.ip_network(ip, strict=False) for ip in ipv6addr_formatted]
    ip_netws = ipv4_netws + ipv6_netws
    # netws are arrays of ip network, used later to check whether an ip is in the network

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
            traffic_type = check_in_out_internal(c.ip.src, c.ip.dst, ip_netws)
            ipsrc = c.ip.src
            ipdst = c.ip.dst
        elif(c.layers[1].version.show == "6"):
            dev_name = get_device_of_packet(c.ipv6.src, c.ipv6.dst)
            traffic_type = check_in_out_internal(c.ipv6.src, c.ipv6.dst, ip_netws)
            ipsrc = c.ipv6.src
            ipdst = c.ipv6.dst
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
            if(ipu.is_in_not_cache(c.ip.src, True) and ipu.is_in_not_cache(c.ip.dst, True)):
                # Do nothing, the pair src<->dst was already identified as not containing a cloud service provider
            elif(ipu.check_Google(c.ip.src, True) or ipu.check_Google(c.ip.dst, True)):
                # This is a Google Cloud related packet
                mstamp.devices[dev_name].services_ipv4["Google"] += pack_len
            elif(ipu.check_AWS(c.ip.src, True) or ipu.check_AWS(c.ip.dst, True)):
                # This is an AWS related packet
                mstamp.devices[dev_name].services_ipv4["AWS"] += pack_len
            elif(ipu.check_Azure(c.ip.src, True) or ipu.check_Azure(c.ip.dst, True)):
                # This is an Azure related packet
                mstamp.devices[dev_name].services_ipv4["Azure"] += pack_len
            else:
                ipu.add_to_not_cache(c.ip.src, True)
                ipu.add_to_not_cache(c.ip.dst, True)
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
            if(ipu.is_in_not_cache(c.ip.src, False) and ipu.is_in_not_cache(c.ip.dst, False)):
                # Do nothing, the pair src<->dst was already identified as not containing a cloud service provider
            elif(ipu.check_Google(c.ipv6.src, False) or ipu.check_Google(c.ipv6.dst, False)):
                # This is a Google Cloud related packet
                mstamp.devices[dev_name].services_ipv6["Google"] += pack_len
            elif(ipu.check_AWS(c.ipv6.src, False) or ipu.check_AWS(c.ipv6.dst, False)):
                # This is an AWS related packet
                mstamp.devices[dev_name].services_ipv6["AWS"] += pack_len
            elif(ipu.check_Azure(c.ipv6.src, False) or ipu.check_Azure(c.ipv6.dst, False)):
                # This is an Azure related packet
                mstamp.devices[dev_name].services_ipv6["Azure"] += pack_len
            else:
                ipu.add_to_not_cache(c.ip.src, False)
                ipu.add_to_not_cache(c.ip.dst, False)
        #check if the packets are encrypted
        encrypted_packet_types=["QUIC", "ICMP", "TCP", "UDP", "TLS"]
        if(any(encrypted_packet_types) in c):
            mstamp.devices[dev_name].total_enc_count+=1
            mstamp.devices[dev_name].total_enc_size +=pack_len
                

        proto_name = c.frame_info.protocols
        if(proto_name in mstamp.devices[dev_name].proto):
            mstamp.devices[dev_name].proto[proto_name] += pack_len
        else:
            mstamp.devices[dev_name].proto[proto_name] = pack_len

        # Check if this is a DNS packet
        if("DNS" in c):
            dns_name = c.dns.qry_name
            if(not dns_name in mstamp.devices[dev_name].dns):
                mstamp.devices[dev_name].dns.append(dns_name)

        # Check if this is a HTTP packet
        if("HTTP" in c):
            # Unencrypted traffic that we want to log the service of
            in_out = check_in_out_internal(ipsrc, ipdst, ip_netws)
            service_ip = ""
            if(in_out == 0):
                # incoming traffic: service-ip = src
                service_ip = ipsrc
            elif(in_out == 1):
                # outgoing traffic: service-ip = dst
                service_ip = ipdst
            
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

    print("Removing raw file", file_name)

    if os.path.exists(file_name):
        os.remove(file_name)


if __name__ == "__main__":
    main()
