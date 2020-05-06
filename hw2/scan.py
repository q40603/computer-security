import scapy.all as scapy
import sys


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
    
def spoof(ip):
    pkt = send(ARP(op=ARP.who_has, psrc="192.168.5.51", pdst=ip))
    x = sniff(filter="arp", count=10, timeout=2)
    print (x.summary())
    print ("done")

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
        spoof(client["ip"])





scan_result = scan(sys.argv[1])
print_result(scan_result)
