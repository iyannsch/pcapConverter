#!/bin/bash
# Bash file for downloading and updating the used IPs of known cloud providers
# The files are provided via https://github.com/lord-alfred/ipranges

# Google (Cloud & GoogleBot)
wget -O google_ipv4.txt "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv4_merged.txt"
wget -O google_ipv6.txt "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv6_merged.txt"

# AWS
wget aws_ipv4.txt "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv4_merged.txt"
wget aws_ipv6.txt "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv6_merged.txt"

# Azure
wget azure_ipv4.txt "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv4_merged.txt"
wget azure_ipv6.txt "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv6_merged.txt"
