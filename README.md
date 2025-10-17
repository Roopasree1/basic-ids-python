# Basic IDS Project

This repository contains:
- target/ : IDS code (target/basic_ids.py)
- attacker/ : testing scripts (attacker/attacker_tests.sh)

## How to run

### On Target (IDS)
1. Install dependencies (prefer system packages or venv):
   - System (Debian/Kali): `sudo apt install python3-scapy python3-colorama`
   - or use a virtual environment:
     ```
     python3 -m venv venv
     source venv/bin/activate
     pip install -r requirements.txt
     ```
2. Run as root (required to sniff):
   `sudo python3 target/basic_ids.py`

### On Attacker
1. Install tools: `sudo apt update && sudo apt install -y nmap hping3`
2. Run attacker script (edit TARGET IP inside script):
   `./attacker/attacker_tests.sh`

**Warning:** Only run attacker scripts against your own lab VMs or authorized systems.

## Files
- `target/basic_ids.py` — the IDS script (sniffs packets, logs alerts)
- `attacker/attacker_tests.sh` — simple scripts to generate test traffic
- `.gitignore` — files to ignore (logs, venvs, keys)
- `requirements.txt` — Python dependencies
