#!/bin/bash
# Script for cronjob. Captures 15 minutes of traffic and preprocesses it
FILENAME=raw_$(date --iso-8601=seconds).pcap
INTERFACE=interface # Change interface here
DURATION=900 # Duration in seconds
PATH_JSONDB=data/db.json # Path to JSON db
timeout --preserve-status $DURATION tcpdump -i $INTERFACE -w $FILENAME \
        && python main.py $FILENAME $DURATION $PATH_JSONDB
