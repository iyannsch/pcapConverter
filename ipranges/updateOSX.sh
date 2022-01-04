#!/bin/bash
# Bash file for downloading and updating the used IPs of known cloud providers
# The files are provided via https://github.com/lord-alfred/ipranges

# Google (Cloud & GoogleBot)
curl "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv4_merged.txt" > google_ipv4.txt
curl "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv6_merged.txt" > google_ipv6.txt

# AWS
curl "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv4_merged.txt" > aws_ipv4.txt
curl "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv6_merged.txt" > aws_ipv6.txt

# Azure
curl "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv4_merged.txt" > azure_ipv4.txt
curl "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv6_merged.txt" > azure_ipv6.txt
