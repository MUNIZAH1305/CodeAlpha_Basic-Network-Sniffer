# CodeAlpha_Basic-Network-Sniffer
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Use the correct interface (e.g., "Ethernet")
sniff(iface="Ethernet", prn=packet_callback, count=10)
