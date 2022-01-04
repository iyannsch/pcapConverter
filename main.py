import sys
import os
import pyshark

usage = """usage: ./main.py [.pcap FILE]"""

def main():
    if(len(sys.argv) < 2):
        print(usage)
        exit(1)
    file_name = sys.argv[1]
    print("Parsing", file_name)
    cap = pyshark.FileCapture(file_name)
    print(cap[0])

if __name__ == "__main__":
    main()
