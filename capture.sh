#!/bin/bash
# Script for cronjob. Captures 15 minutes of traffic and preprocesses it
FILENAME=raw_$(date --iso-8601=seconds).pcap
INTERFACE=wlan0 # Change interface here
DURATION=900 # Duration in seconds
PATH_JSONDB=data/db.json # Path to JSON db
SNAPLEN=500 # Snap Length
timeout --preserve-status $DURATION tcpdump -i $INTERFACE -s $SNAPLEN -w $FILENAME \
        && python main.py $FILENAME $PATH_JSONDB $DURATION
