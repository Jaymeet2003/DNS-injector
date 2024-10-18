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


def process_packet(packet):
    # Check if the packet has a DNS layer
    if scapy.DNS in packet:
        dns_layer = packet[scapy.DNS]
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        if scapy.TCP in packet:
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif scapy.UDP in packet:
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
        print(f"DNS request: {dns_layer.show()}")
        print(src_ip, src_port,dst_ip,dst_port,dns_layer.id)
    
    
scapy.sniff(iface = interface, prn=process_packet)




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
                
                