from scapy.all import *
from scapy.utils import rdpcap
import random

pkts=rdpcap(sys.argv[1]) 

for i in range(100):
	for pkt in pkts:
		pkt[IP].src= "192.168.0.{}".format(random.randint(2, 100))
		wrpcap('try.pcap', pkt, append = True)