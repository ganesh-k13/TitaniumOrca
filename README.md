# Titanium Orca

A DDoS and port scan analysis tool

### Prerequisites

pandas==0.17.1
scapy_python3==0.23
dpkt==1.9.1
scapy==2.4.0rc4
tabulate==0.8.2

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
	
	Other PCAPS included are: [TODO]
	
```

* [Python](https://docs.python.org/3/) - Main Platform
* [DPKT](https://pypi.python.org/pypi/dpkt) - Main Packet Analser 

## Authors

* **Ganesh K.** - [DarkFate13](https://github.com/DarkFate13)

## Acknowledgments

This is developed as an assignment for Computer Networks Security Course 
Reason for name: "Wave-hunting" Orca whales spy-hop to locate Weddell seals, crabeater seals, leopard seals, and penguins resting on ice floes, and then swim in groups to create waves that wash over the floe. Similar to port scans and DDos.