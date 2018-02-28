import dpkt
import sys
import socket
import traceback
from ipaddress import ip_address
import json
from tabulate import tabulate
from pprint import pprint
class TitaniumOrca:
	
	def __init__(self, filename):
		self.filename = filename
		self.malicious_ip = dict()
		self.attackers = list()
		self.port_list = dict()
	def __check_if_port_scan(self, port_list):
		return len(port_list) - len(set([i for i in range(min(port_list), max(port_list)+1)])) <= 10
	
	def parse(self):
		# Open pcap file
		with open(self.filename, 'rb') as f:
			pcap = dpkt.pcap.Reader(f) # Parse file
			print("Parsing....")
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
					port = tcp.dport
					src_ip_addr_str = socket.inet_ntoa(ip.src)
					
					# IF Packet is a TCP-SYN
					if(syn_flag == True and ack_flag == False):
						# malicious_ip maps: ip->[SYN_count, non_SYN_count]
						self.malicious_ip[ip.src] = self.malicious_ip.get(ip.src, [0, 0, []])
						self.malicious_ip[ip.src][0]+=1
						self.malicious_ip[ip.src][2].append(port)
					else:
						self.malicious_ip[ip.src] = self.malicious_ip.get(ip.src, [0, 0, []])
						self.malicious_ip[ip.src][1]+=1
						self.malicious_ip[ip.src][2].append(port)
					# print(syn_flag, ack_flag, ip.dst, src_ip_addr_str, port)
					
				except:
					traceback.print_exc() # [IMP]: Uncomment while developing
		
			return self.__table(self.__detect_attackers(), ["IP Adress", "Port"])
	
	def get_count(self):
		ip_count = list()
		for ip, count in self.malicious_ip.items():
			if(count[0] > 3 * count[1]):
				ip_count.append([socket.inet_ntoa(ip), count[0]])
		return self.__table(ip_count, ["IP Adress", "Count"])
	
	def __detect_attackers(self):
		
#		pprint(self.malicious_ip.items())
		for ip, count in self.malicious_ip.items():
			if(count[0] > 3 * count[1]):
				for port in count[2]:
					self.port_list[socket.inet_ntoa(ip)] = self.port_list.get(socket.inet_ntoa(ip), [])
					self.port_list[socket.inet_ntoa(ip)].append(port)
					self.attackers.append([socket.inet_ntoa(ip), int(port)])
		
		return self.attackers
		
	def to_json(self):
		with open('malicious_ip.json', 'w') as f:
			json.dumps(f, self.malicious_ip, indent = 4)
	
	def __call__(self):
		#print(self.port_list)
		return (self.__check_if_port_scan(self.port_list['192.168.100.103']))
	
	def __table(self, info, headers):
		return tabulate(info, headers = headers, tablefmt="fancy_grid")
	
if __name__ == "__main__":
	s = TitaniumOrca(sys.argv[1])

	print(s.parse())
	print(s.get_count())
	# print(tabulate(s.parse()))
	# print(s())
		# print(i)
	# s.to_json()
