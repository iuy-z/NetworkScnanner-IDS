**Operating System Compatibility**
Supported OS: Linux-based systems (e.g., Ubuntu).
Reason: The tool requires raw packet capturing, which works best on Linux environments due to its compatibility with Scapy and network interfaces.

**Prerequisites**
1) Python Installation
2) Install Scapy
Install the Scapy library using pip:
      pip install scapy
3) Run with Root Privileges i.e. sudo

**Steps to Run**
1) Download the Script
Save the script (updatedPortScan.py) on your computer.
2) Open Terminal
Navigate to the directory containing the script:
      cd /path/to/your/script
3) Choose Network Interface
Identify your active network interface. Common interfaces are:
      eth0 for wired connections.
      wlan0 for wireless connections.
To check available interfaces, run:

ifconfig

4) Run the Script
Use the following command to start the detection system:

sudo python3 updatedPortScan.py
5) Input the Interface
The script will prompt you to enter the network interface (e.g., eth0 or wlan0). Type the interface name and press Enter. Preferable eth0

**Alerts and Monitoring**
The script will begin sniffing live network traffic.
It will display real-time alerts for detected threats, such as:
1) ARP spoofing.
2) DNS spoofing.
3) DoS/DDoS attacks.
4) Port scanning.

**Important Notes**
Ensure Proper Permissions
The user must have sudo privileges to capture packets.

Interface-Specific Use

For wired networks, use eth0.
For wireless networks, use wlan0.
Stop the Script
To stop the script, press Ctrl + C.

Customizable Thresholds
Modify the detection thresholds in the script as needed to suit your network environment.
