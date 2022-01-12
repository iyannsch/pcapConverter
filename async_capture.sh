#!/bin/bash
# Asynchronous processing of all files
DURATION=900 # Duration in seconds
PATH_JSONDB=data/db.json # Path to JSON db

ls raw_* | xargs -t -I '{}' python main.py '{}' $PATH_JSONDB $DURATION
