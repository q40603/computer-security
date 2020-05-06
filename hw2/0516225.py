import subprocess
from scapy.all import *
output = subprocess.check_output(("arp"))
print(output)
arp_packt = ARP(op=2, pdst="192.168.159.131", hwdst="00:0c:29:03:3e:ae", psrc="10.1.1.1")
arp_packt.show()
print(arp_packt.summary())
