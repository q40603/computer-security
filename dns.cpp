#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

int main(int argc, char* const argv[]) {

    int sd;
    char buffer[4096];
    struct iphdr *iph = (struct iphdr *) buffer;
    struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr));

    // fill ip header
    iph->version = 4;
    iph->tos = 0;
    iph->ihl = 5;                       // Internet Header Length (IHL), which is the number of 32-bit words in the header
    iph->id = htons(6016);                   // id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(argv[1]);         // ip spoof
    iph->daddr = inet_addr(argv[3]);
    // iph->tot_len =
    // iph->check  re-compute


    udph->source = htons(atoi(argv[2]));
    udph->dest = htons(53);                 // not sure
    //udph->len =
    //udph->check = 

	
	// dns query in udp payload
	


    // create a socket
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("error when create socket");
        exit(0);
    }

}
