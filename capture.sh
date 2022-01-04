#!/bin/bash
# Script for cronjob. Captures 15 minutes of traffic and preprocesses it
FILENAME=raw_$(date --iso-8601=seconds).pcap
INTERFACE=interface # Change interface here
timeout --preserve-status 15m tcpdump -i $INTERFACE -w $FILENAME \
        && converter-script $FILENAME # TODO
