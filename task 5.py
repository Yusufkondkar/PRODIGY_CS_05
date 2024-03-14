from scapy.all import IP, TCP, UDP, Ether, sniff


def packet_callback(packet):
    if Ether in packet and IP in packet:
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        protocol = ""
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = packet[TCP].payload
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = packet[UDP].payload
        else:
            protocol = "Other"
            src_port = "-"
            dst_port = "-"
            payload = packet.payload

        print(f"Source MAC: {eth_src}, Destination MAC: {eth_dst}")
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        print("Payload:")
        print(payload)

# Start sniffing packets on the network with a maximum of 20 packets
sniff(prn=packet_callback, store=False, count=20)
