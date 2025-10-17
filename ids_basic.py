#!/usr/bin/env python3 
"""
ids_basic.py - Minimal time-window IDS
Alerts when a source IP sends more than THRESHOLD packets within WINDOW seconds.
Logs to basic_ids.log
"""
import time
from collections import defaultdict, deque
from scapy.all import sniff, IP
import logging

# Demo settings - easy to trigger
WINDOW = 5          # seconds
THRESHOLD = 5       # packets in WINDOW -> alert
LOGFILE = "ids_basic.log"

# Data structures
packet_times = defaultdict(lambda: deque())
logging.basicConfig(filename=LOGFILE, level=logging.INFO,
                    format="%(asctime)s %(message)s")

def clean_deque(dq, window):
    now = time.time()
    while dq and (now - dq[0] > window):
        dq.popleft()

def detect(packet):
    if not packet.haslayer(IP):
        return
    src = packet[IP].src
    now = time.time()
    dq = packet_times[src]
    dq.append(now)
    clean_deque(dq, WINDOW)
    count = len(dq)
    if count > THRESHOLD:
        msg = f"[ALERT] {src} sent {count} packets in last {WINDOW}s"
        print(msg)
        logging.info(msg)

def main(interface=None):
    print("Basic IDS starting...")
    print(f"Window={WINDOW}s, Threshold={THRESHOLD} pkts")
    try:
        sniff(prn=detect, store=False, iface=interface)
    except PermissionError:
        print("PermissionError: run as root to sniff packets.")
    except KeyboardInterrupt:
        print("\nStopped by user. Exiting.")

if __name__ == '__main__':
    main()
PY

