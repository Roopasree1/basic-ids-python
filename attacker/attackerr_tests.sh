#!/bin/bash
TARGET=192.168.56.101

echo "1) ping test: 50 rapid pings"
for i in {1..50}; do ping -c1 -W1 $TARGET & done
sleep 2

echo "2) nmap quick port scan"
nmap -p 1-200 -T4 $TARGET

echo "3) hping3 SYN bursts (100 packets)"
for i in {1..100}; do sudo hping3 -c 1 -S -p 80 $TARGET & done

echo "Done attacker tests"
SH
