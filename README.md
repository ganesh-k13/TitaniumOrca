# Titanium Orca

A DDoS and port scan analysis tool

### Prerequisites

* scapy_python3==0.23
* dpkt==1.9.1
* scapy==2.4.0rc4
* tabulate==0.8.2

### Installing

First install all prerequisites

```
sudo pip3 install -r requirements.txt
```
## Running

``` 
python3 analyser.py [PARAMETERS]...

PARAMETERS:
    /path/to/*.pcap/file
	
	The common pacaps for evaluation:
		- pcap/namp/nmap_standard_scan
		- pcap/syn_attack.pcap
	
	Other PCAPS included are:
    pcap
    ├── Attack.pcap #Sample TCP-HALF-OPEN attack
    ├── hping_syn.pcap # Hping small output
    ├── nmap # NMAP Ouptut files [SEE README.txt]
    │   ├── nmap_ACK_scan_on_port_80
    │   ├── nmap_ACK_scan_on_port_80_2
    │   ├── nmap_OS_scan
    │   ├── nmap_OS_scan_succesful
    │   ├── nmap_standard_scan # Standard Portscan
    │   └── README.txt
    ├── portscan.pcap 
    ├── Sample.pcap
    └── syn_attack.pcap #Real Life DOS attack on a commercial server

 
EXAMPLE: python3 analyser.py pcap/namp/nmap_standard_scan # RUN THIS FOR EVALUATAION
	
```

## Tools

* [Python](https://docs.python.org/3/) - Main Platform
* [DPKT](https://pypi.python.org/pypi/dpkt) - Main Packet Analyzer 
* [scapy](https://github.com/secdev/scapy) - Main Packet Manipulator 

## Authors

* **Ganesh K.** - [DarkFate13](https://github.com/DarkFate13)
* **Mohammed Salamuddin**

## Acknowledgments

* This is developed as an assignment for Computer Networks Security Course 
* Reason for name: "Wave-hunting" Orca whales spy-hop to locate prey on ice floes, and then swim in groups and attack together in parallel to create waves that wash over the floe. Similar to port scans and DDos.