#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<netinet/ether.h>

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */

    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

int main(){
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;	
	char *dst;

	int res;

	unsigned char *data;

	
	dev = pcap_lookupdev(errbuf);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL) {
		printf("Couldn't open device.\n");
		return 0;
	}

	libnet_ethernet_hdr *eth_hdr;

	while(1)
	{
		int i;
		res = pcap_next_ex(handle, &header, &pkt_data);
		if(res <= 0) continue;
		//printf("%u \n", (unsigned int)eth_hdr->ether_type);
		eth_hdr = (libnet_ethernet_hdr*)pkt_data;
		

		printf("SRC MAC address : ");
		for(i=0;i<=5;i++)printf("%02x ",eth_hdr->ether_shost[i]);
		printf("\nDST MAC address : ");
		for(i=0;i<=5;i++)printf("%02x ",eth_hdr->ether_dhost[i]);
		printf("\n");

		if((ntohs(eth_hdr->ether_type))==0x0800){
			libnet_ipv4_hdr *ip_hdr;

			ip_hdr = (libnet_ipv4_hdr*)(pkt_data+14);
		
			printf("SRC ip : %s\n", inet_ntoa(ip_hdr->ip_src));
			printf("DST ip :%s\n", inet_ntoa(ip_hdr->ip_dst));
			
			if((ip_hdr->ip_p)==0x06){
				libnet_tcp_hdr *tcp_hdr;
				tcp_hdr = (libnet_tcp_hdr*)(pkt_data+14+(4*(ip_hdr->ip_hl)));
				printf("SRC port : %u\n", ntohs(tcp_hdr->th_sport));
				printf("DST port : %u\n", ntohs(tcp_hdr->th_dport));

				//printf("tcp lengths : %u(%2x)\n", (tcp_hdr->th_off)*4,(tcp_hdr->th_off)*4 );
				//printf("ip hdr lengths: %u(%2x)\n",(ip_hdr->ip_hl) *4,(ip_hdr->ip_hl) *4);
				
				//printf("total : %u(%2x)\n",ntohs(ip_hdr ->ip_len), ntohs(ip_hdr -> ip_len));

				//printf("data lengths: %u(%2x)\n", (ntohs(ip_hdr->ip_len)-(4*ip_hdr->ip_hl)-(4*tcp_hdr->th_off)),(ntohs(ip_hdr->ip_len)-(4*ip_hdr->ip_hl)-(4*tcp_hdr->th_off)));

				//printf("ip hdr start : %u(%2x)\n", *(pkt_data+14),*(pkt_data+14));
				//printf("tcp hdr start : %u(%2x)\n", *(pkt_data+14+(4*(ip_hdr->ip_hl))),*(pkt_data+14+(4*(ip_hdr->ip_hl))));

				//data = (unsigned char *)(pkt_data+14+(4*(ip_hdr->ip_hl)) + (4 * tcp_hdr->th_off));

				//printf("data start : %u(%2x)\n",*(pkt_data+14+(4*(ip_hdr->ip_hl)) + (4 * tcp_hdr->th_off)),*(pkt_data+14+(4*(ip_hdr->ip_hl)) + (4 * tcp_hdr->th_off)));
				
				/*for(int i = 0;i<(ntohs(ip_hdr->ip_len)-(4*ip_hdr->ip_hl)-(4*tcp_hdr->th_off));i++){
				
				printf("%02x ",data[i]);
				
				}*/
				
				for(int i = 0;i<(ntohs(ip_hdr->ip_len)-(4*ip_hdr->ip_hl)-(4*tcp_hdr->th_off));i++){
				
				printf("%02x ",pkt_data[14+(4*(ip_hdr->ip_hl)) + (4 * tcp_hdr->th_off)+i]);
				
				}
			}
		}
		printf("\n\n");
	}		
	

}
