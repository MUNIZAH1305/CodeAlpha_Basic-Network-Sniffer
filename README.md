# BASIC NETWORK SNIFFER
Basic Network Sniffer is a lightweight tool designed to monitor and analyze network traffic in real-time. This project provides developers and cybersecurity enthusiasts with a foundation to explore networking concepts, packet inspection, and protocol analysis.

# 🚀 Features
Real-Time Packet Capture:Monitors live network traffic.
Protocol Analysis: Supports decoding of TCP, UDP, ICMP, and other protocols.
Customizable Filters: Enables targeted packet inspection to focus on specific data streams.
User-Friendly Output: Displays captured packets in a structured and readable format.
Modular Codebase: Easy to extend and adapt for advanced use cases.
# 📚 Use Cases
Understanding the basics of networking and packet structures.
Gaining hands-on experience in network security and traffic analysis.
Learning to implement packet filtering and decoding in Python (or your project language).
# 🛠️ Technologies Used
Language: Python
Libraries: Scapy, socket, and other relevant tools
# 🤝 Contributions
Contributions are welcome! If you’d like to enhance this project or add new features, feel free to submit a pull request or open an issue.

# 📜 License
This project is licensed under the MIT License.
# CodeAlpha_Basic-Network-Sniffer
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Use the correct interface (e.g., "Ethernet")
sniff(iface="Ethernet", prn=packet_callback, count=10)
