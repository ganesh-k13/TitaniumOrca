from scapy.all import *
from scapy.utils import rdpcap
import random

pkts=rdpcap(sys.argv[1])  # could be used like this rdpcap("filename",500) fetches first 500 pkts

for i in range(100):
	for pkt in pkts:
		pkt[IP].src= "192.168.0.{}".format(random.randint(2, 100)) # i.e new_src_ip="255.255.255.255"
		wrpcap('try.pcap', pkt, append = True)