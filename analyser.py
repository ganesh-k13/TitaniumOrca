import dpkt
import sys
import socket
import traceback
from ipaddress import ip_address
import json

class TitaniumOrca:
	
	def __init__(self, filename):
		self.filename = filename
		self.malicious_ip = dict()
		self.attackers = list()
	
	def __check_if_port_scan(self, port_list):
		return len(port_list) - len(set([i for i in range(min(port_list), max(port_list)+1)])) <= 10
	
	def parse(self):
		# Open pcap file
		with open(self.filename, 'rb') as f:
			pcap = dpkt.pcap.Reader(f) # Parse file
			for ts, buf in pcap:
				try:
					# Extract TCP data if present else fail silently
					eth = dpkt.ethernet.Ethernet(buf)
					ip = eth.data
					tcp = ip.data
					
					# Check if SYN ACK is set. 
					syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
					ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
					
					# Find port number and src, dest IPs
					# [TODO]: FIND PORT, dest
					src_ip_addr_str = socket.inet_ntoa(ip.src)
					
					# IF Packet is a TCP-SYN
					if(syn_flag == True and ack_flag == False):	
						# malicious_ip maps: ip->[SYN_count, non_SYN_count]
						self.malicious_ip[ip.src] = self.malicious_ip.get(ip.src, [0, 0])
						self.malicious_ip[ip.src][0]+=1
					else:
						self.malicious_ip[ip.src] = self.malicious_ip.get(ip.src, [0, 0])
						self.malicious_ip[ip.src][1]+=1
					print(syn_flag, ack_flag, ip.dst, src_ip_addr_str)
				except:
					traceback.print_exc() # [IMP]: Uncomment while developing
		
			return self.__detect_attackers()
	
	def __detect_attackers(self):
		
		for ip, count in self.malicious_ip.items():
			if(count[0] > 3 * count[1]):
				self.attackers.append([ip, count[0]])
		
		return self.attackers
		
	def to_json(self):
		with open('malicious_ip.json', 'w') as f:
			json.dumps(f, self.attackers, indent = 4)
	
	def __call__(self):
		return self.__check_if_port_scan(range(10))
	
if __name__ == "__main__":
	s = TitaniumOrca(sys.argv[1])
	
	# for i in s.parse():
		# print(socket.inet_ntoa(i[0]), i[1])
		
	print(s())
		# print(i)
	# s.to_json()