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

## Sample Input/Output

```
$ python3 analyser.py pcap/portscan.pcap

Parsing....
Malicious IP Addresses with their SYN Packet Counts:
╒══════════════╤═════════╕
│ IP Adress    │   Count │
╞══════════════╪═════════╡
│ 10.100.25.14 │      29 │
╘══════════════╧═════════╛
Do you wish to see the ports attacked/scanned? (y/n) : y
╒══════════════╤════════╕
│ IP Adress    │   Port │
╞══════════════╪════════╡
│ 10.100.25.14 │    139 │
├──────────────┼────────┤
│ 10.100.25.14 │    135 │
├──────────────┼────────┤
│ 10.100.25.14 │    445 │
├──────────────┼────────┤
│ 10.100.25.14 │     80 │
├──────────────┼────────┤
│ 10.100.25.14 │     22 │
├──────────────┼────────┤
│ 10.100.25.14 │    515 │
├──────────────┼────────┤
│ 10.100.25.14 │     23 │
├──────────────┼────────┤
│ 10.100.25.14 │     21 │
├──────────────┼────────┤
│ 10.100.25.14 │   6000 │
├──────────────┼────────┤
│ 10.100.25.14 │   1025 │
├──────────────┼────────┤
│ 10.100.25.14 │     25 │
├──────────────┼────────┤
│ 10.100.25.14 │    111 │
├──────────────┼────────┤
│ 10.100.25.14 │   1028 │
├──────────────┼────────┤
│ 10.100.25.14 │   9100 │
├──────────────┼────────┤
│ 10.100.25.14 │   1029 │
├──────────────┼────────┤
│ 10.100.25.14 │     79 │
├──────────────┼────────┤
│ 10.100.25.14 │    497 │
├──────────────┼────────┤
│ 10.100.25.14 │    548 │
├──────────────┼────────┤
│ 10.100.25.14 │   5000 │
├──────────────┼────────┤
│ 10.100.25.14 │   1917 │
├──────────────┼────────┤
│ 10.100.25.14 │     53 │
├──────────────┼────────┤
│ 10.100.25.14 │    161 │
├──────────────┼────────┤
│ 10.100.25.14 │   9001 │
├──────────────┼────────┤
│ 10.100.25.14 │  65535 │
├──────────────┼────────┤
│ 10.100.25.14 │    443 │
├──────────────┼────────┤
│ 10.100.25.14 │    113 │
├──────────────┼────────┤
│ 10.100.25.14 │    993 │
├──────────────┼────────┤
│ 10.100.25.14 │   8080 │
├──────────────┼────────┤
│ 10.100.25.14 │   2869 │
╘══════════════╧════════╛
Do you wish to see if it was a port scan? (y/n): y
IP:  10.100.25.14  : True
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