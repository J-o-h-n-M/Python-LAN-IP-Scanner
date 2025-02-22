# Network Scanner - Device Discovery and Port Scanning Tool

A Python script to discover active devices on your local network, identify open ports, and resolve hostnames. 
Optimized for speed with concurrent processing and clean tabulated output.


## Features
- 🚀 **ARP-based network scanning** for device discovery
- 🔍 **Concurrent port scanning** (500+ threads)
- 🌐 **Hostname resolution** via reverse DNS
- 📊 **Clean tabulated output** using `tabulate`
- ⚡ **Optimized performance** (3-5x faster than basic scanners)

## Requirements
- Python 3.6+
- Linux/Unix system (for raw socket support)
- Root privileges (for ARP scanning)


# Install dependencies
pip install scapy tabulate


# Example of output
| IP Address    | MAC Address       | Hostname          | Open Ports  |
|---------------|-------------------|-------------------|-------------|
| 192.168.1.1   | 00:1a:2b:3c:4d:5e | router.lan        | 80,443      |
| 192.168.1.101 | a0:b1:c2:d3:e4:f5 | desktop-pc        | 22,3389     |
| 192.168.1.102 | 08:00:27:ab:cd:ef | nas.local         | 445,9000    |
