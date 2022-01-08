import ipaddress

class IPUtils:
    # define and import ipranges
    file = open("ipranges/google_ipv4.txt", "r")
    GOOGLE_IPV4 = file.read().split('\n')
    GOOGLE_IPV4.pop()
    file = open("ipranges/google_ipv6.txt", "r")
    GOOGLE_IPV6 = file.read().split('\n')
    GOOGLE_IPV6.pop()
    file = open("ipranges/aws_ipv4.txt", "r")
    AWS_IPV4 = file.read().split('\n')
    AWS_IPV4.pop()
    file = open("ipranges/aws_ipv6.txt", "r")
    AWS_IPV6 = file.read().split('\n')
    AWS_IPV6.pop()
    file = open("ipranges/azure_ipv4.txt", "r")
    AZURE_IPV4 = file.read().split('\n')
    AZURE_IPV4.pop()
    file = open("ipranges/azure_ipv6.txt", "r")
    AZURE_IPV6 = file.read().split('\n')
    AZURE_IPV6.pop()
    file.close()

    ip4_cache = {}
    ip6_cache = {}

    ip4_not_cache = []
    ip6_not_cache = []

    def is_in_not_cache(self, ipadr, isV4):
        if(isV4 == True):
            if(ipadr in self.ip4_not_cache):
                return True
        else:
            if(ipadr in self.ip6_not_cache):
                return True
        return False

    def check_Google(self, ipadr, isV4):
        if(isV4 == True):
            if(ipadr in self.ip4_cache and self.ip4_cache[ipadr] == "Google"):
                return True
            for ipnet in self.GOOGLE_IPV4:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    self.ip4_cache[ipadr] = "Google"
                    return True
        else:
            if(ipadr in self.ip6_cache and self.ip6_cache[ipadr] == "Google"):
                return True
            for ipnet in self.GOOGLE_IPV6:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    self.ip6_cache[ipadr] = "Google"
                    return True
        return False
    
    def check_AWS(self, ipadr, isV4):
        if(isV4 == True):
            if(ipadr in self.ip4_cache and self.ip4_cache[ipadr] == "AWS"):
                return True
            for ipnet in self.AWS_IPV4:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    self.ip4_cache[ipadr] = "AWS"
                    return True
        else:
            if(ipadr in self.ip6_cache and self.ip6_cache[ipadr] == "AWS"):
                return True
            for ipnet in self.AWS_IPV6:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    self.ip6_cache[ipadr] = "AWS"
                    return True
        return False

    def check_Azure(self, ipadr, isV4):
        if(isV4== True):
            if(ipadr in self.ip4_cache and self.ip4_cache[ipadr] == "Azure"):
                return True
            for ipnet in self.AZURE_IPV4:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    self.ip4_cache[ipadr] = "Azure"
                    return True
        else:
            if(ipadr in self.ip6_cache and self.ip6_cache[ipadr] == "Azure"):
                return True
            for ipnet in self.AZURE_IPV6:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    self.ip6_cache[ipadr] = "Azure"
                    return True
        return False
    
