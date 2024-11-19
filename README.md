
# DNS Injector Tool

## Overview
This tool is designed to sniff DNS packets on a specified network interface and inject forged DNS responses, redirecting traffic to an attacker's IP address. The program is built using the Scapy library for crafting and sending packets.

**Disclaimer**: This code is for educational and security research purposes only. Unauthorized use is illegal and unethical.

## Prerequisites
- Python 3.x
- Scapy library (install with `pip install scapy`)

## Usage
### Command-line Arguments
- `-i <interface>`: Specifies the network interface to use for sniffing and injection. Default is `en0`.
- `-h <hostnames>`: Specifies a file containing hostname-IP pairs to customize DNS responses.

### Hostname File Format
Each line should have the format:
```
<IP>,<hostname>
```
Example:
```
192.168.1.100,example.com
```

### Running the Program
```bash
python dnsinjector.py [-i interface] [-h hostnames]
```

### Example
To run the script using interface `en0` and a hostname file `hostnames.txt`:
```bash
python dnsinjector.py -i en0 -h hostnames.txt
```

## How It Works
1. The tool sniffs DNS packets on the specified interface.
2. When a DNS query packet is detected:
   - It checks if the queried domain matches any in the provided hostname file.
   - If a match is found, it returns the corresponding IP; otherwise, it uses the attacker's IP.
3. A forged DNS response packet is constructed and sent, redirecting traffic to the specified IP.

## Code Structure
- **get_hijack_ip(query)**: Returns the appropriate IP for the given domain.
- **inject(packet, attacker_ip, interface)**: Inspects and modifies DNS query packets, sending forged responses.
- **Main Execution**: Validates command-line arguments, loads the hostname file, and starts sniffing traffic.

## Important Notes
- Ensure you have the necessary permissions to run this script (root/admin).
- Use responsibly and in compliance with all applicable laws and ethical guidelines.

## License
This tool is provided as-is with no warranty. It is intended for educational purposes only.
