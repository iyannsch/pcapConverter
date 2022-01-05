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

    def check_Google(self, ipadr, isV4):
        if(isV4 == True):
            for ipnet in self.GOOGLE_IPV4:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    return True
        else:
            for ipnet in self.GOOGLE_IPV6:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    return True
        return False
    
    def check_AWS(self, ipadr, isV4):
        if(isV4 == True):
            for ipnet in self.AWS_IPV4:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    return True
        else:
            for ipnet in self.AWS_IPV6:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    return True
        return False

    def check_Azure(self, ipadr, isV4):
        if(isV4== True):
            for ipnet in self.AZURE_IPV4:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    return True
        else:
            for ipnet in self.AZURE_IPV6:
                if(ipaddress.ip_address(ipadr) in ipaddress.ip_network(ipnet)):
                    return True
        return False
    
