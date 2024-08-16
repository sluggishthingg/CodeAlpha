from scapy.all import sniff, ARP, ICMP, BOOTP, IP, TCP, UDP

def packet_callback(packet):
    print("Packet received:")
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print("The packet is ARP --")
        print(f"ARP Operation: {arp_layer.op}, Source IP: {arp_layer.psrc}, Source Mac: {arp_layer.hwsrc}, Destination IP: {arp_layer.pdst}, Destination Mac: {arp_layer.hwdst}")
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print(f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")
    elif packet.haslayer(BOOTP):
        bootp_layer = packet[BOOTP]
        print(f"BOOTP Operation: {bootp_layer.op}, Client Hardware Address: {bootp_layer.chaddr}")
    else:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            print(f"IP Packet: Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                print(f"TCP Packet: Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                print(f"UDP Packet: Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
        else:
            print(f"Other packet type: {packet.summary()}")
    print("--------------------")

def main():
    print("Starting packet capture...")
    sniff(filter="", prn=packet_callback, count=10)
    print("Packet capture finished.")

if __name__ == "__main__":
    main()