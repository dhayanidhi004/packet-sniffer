Packet Sniffer in Python
📌 Project Overview

This project is a simple packet sniffer built in Python using the scapy library.
It captures network packets, displays their details, and logs alerts for suspicious activity (e.g., SYN scan detection).

✅ Features

Captures TCP, UDP, and ICMP packets

Displays packet details in the terminal

Logs alerts for potential port scans

Saves logs to a file (sniffer.log)

🛠️ Requirements

Python 3.x

Scapy library

Root/Administrator privileges

Version Control: Git & GitHub

Testing Tools: nmap, curl, ping

🚀 Steps to Run the Project
Step 1: Clone the Repository
git clone https://github.com/dhayanidhi004/packet-sniffer.git
cd packet-sniffer

Step 2: Install Dependencies
pip install scapy

Step 3: Run the Sniffer
sudo python3 packet_sniffer.py

🧪 Testing
Generate Normal Traffic
curl http://example.com
ping 8.8.8.8

Simulate SYN Scan
sudo nmap -sS -p 20-50 127.0.0.1

📄 Sample Output
[+] Packet captured: IP -> TCP
[+] Packet captured: IP -> ICMP
[!] Possible SYN scan detected from 127.0.0.1

📷 Screenshots

VM Network Settings (NAT)

Packet Sniffer running in terminal

Output of curl and ping

Output of nmap scan

GitHub repository page after push

(Add images in your repo and link them here)

✅ Challenges Faced

Internet connectivity issue in VM (fixed by checking NAT settings and DNS config)

Git push failure due to DNS resolution

Handling root privileges for Scapy

📌 Conclusion

This project demonstrates the working of a packet sniffer in Python, providing practical knowledge of network traffic analysis and intrusion detection.
