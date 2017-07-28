
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ether.h>	     // for either_ntoa
#include <netinet/if_ether.h>    // for ehter sturcture
#include <netinet/ip.h>    		 // for ip structure
#include <netinet/tcp.h>  		 // for tcp structure
#include <arpa/inet.h>
// copy struct information Link on End of Code. 
//#include "_My_lib.h"



int _packet_pointer=0; // examplev:v packket[_packet_pointer]

// ETH-IP-TCP-HTTP  Family
void _ip_func(u_char *packet,struct ip *_ip){
//		struct ip *_ip=_ip;
//		_ip=(struct ip*)(&(packet[_packet_pointer])); 
		_packet_pointer+=_ip->ip_hl*4;

		printf("================NETWORK Layer=======================\n");
		printf("\ndst IP : %s\n", inet_ntoa( _ip->ip_dst));
		printf("src IP : %s\n", inet_ntoa( _ip->ip_src));

		switch(_ip->ip_p){
			case 0x06:
				//printf("Protocol : TCP\n");
				_tcp_func(packet);
				break;
			case 0x07:
				printf("Protocol : UDP\n");
				break;
			default:
				printf("Protocol unknown! \n");
				break;
		}

		printf("====================================================\n");
}

void _tcp_func(u_char *packet){
		struct tcphdr *_tcp;	
		_tcp=(struct tcphdr*)(&(packet[_packet_pointer]));
		_packet_pointer+=_tcp->th_off*4;

		printf("================Transport Layer==================\n");
		printf("dst Port : %d\n",ntohs(_tcp->th_dport));
		printf("src Port : %d\n",ntohs(_tcp->th_sport));
		//printf("Sequence    Number : %d\n",_tcp->th_seq);
		//printf("Acknowledge Number : %d\n",_tcp->th_ack);


}




int main(int argc, char *argv[]){
	printf("*START*");
	pcap_t *handle;	
	u_char *packet;
	struct pcap_pkthdr *header;		

	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;		
	bpf_u_int32 mask;	
	bpf_u_int32 net;		


	char filter_exp[] = "port 80";	

// STRAT : STRUCT DECLARATION 
	struct ether_header *_eth;
	struct ip *_ip;
	struct _tcp_set *_tcp;
	char *_data;
	int hdr_length;
// END : STRUCT DECLARATION

	int ck_packet; // check packet, where it rightly receive packets or not.
	int _input=0; // scanf vaiable

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }
	if (pcap_setfilter(handle, &fp) == -1) { fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }




/*
// STRAT : HOW MANY PACKETS ?
		printf("How many Packets do you want to Capture? (1-9) : ");
		scanf("%d",&_input);  
// END : HOW MANY PACKETS ?
*/

//		printf("_input : %d\n",_input);
//START
	while(1){
		ck_packet = pcap_next_ex(handle, &header,&packet);
		_packet_pointer=0;


		if(ck_packet==0){
			printf("ck_packet=0, it means ""TIME OUT""\n");
			continue;   //TIMOUT - keep going
		}
		else if(ck_packet==1){
			_eth=(struct ether_header*)(packet);
			_packet_pointer+=sizeof(struct ether_header);

			_ip=(struct ip*)(&(packet[_packet_pointer])); 

			  //ehter size 14.
//			_tcp=(struct _tcp_set*)(&(packet[sizeof(struct ether_header)+(_ip->ip_hl)*4]));
//			_data=(&(packet[sizeof(struct ether_header)+(_ip->ip_hl)*4+(_tcp->offset)*4]));


// START : BASIC common function
			printf("================DATA LINK Layer=======================\n");
			printf("dst MAC : %s\n", ether_ntoa((struct ether_header*) _eth->ether_dhost));
			printf("src MAC : %s\n", ether_ntoa((struct ether_header*) _eth->ether_shost));
			printf("Type    : %04x\n\n", ntohs(_eth->ether_type));
			printf("=====================================================\n");
// END : BASIC common function	

// START : FIGURE OUT EHTERTPYE
			switch(ntohs(_eth->ether_type)){
				case ETHERTYPE_IP:
					_ip_func(packet,_ip);
					break;
				case ETHERTYPE_ARP:
					//
					break;
				case ETHERTYPE_PUP:
					printf("PUP protocol \n");
					break;
				default:
					break;				
			}
// END : FIGURE OUT EHTERTPYE

/*
			printf("dst IP : %s\n", inet_ntoa( _ip->ip_dst));
			printf("src IP : %s\n", inet_ntoa( _ip->ip_src));
			printf("PROTOCOL : %d\n", _ip->ip_p);
			printf("\ndst Port : %hu\n",ntohs(_tcp->tcp_dst_port));
			printf("src Port : %hu\n",ntohs(_tcp->tcp_src_port));
			
			hdr_length=sizeof(struct ether_header)+(_ip->ip_hl)*4+(_tcp->offset)*4;

			printf("\nTotal Length : %d\n", ntohs(_ip->ip_len)*4);
			printf("Data Length : %d\n", ntohs(_ip->ip_len)*4-hdr_length);
			printf("DATA : ");
			
			for(int i=0; i<ntohs(_ip->ip_len)-hdr_length; i++){
				printf("%c ",_data[i]);
			}			
*/



			

			for(int i=0; i<ntohs(_ip->ip_len)*4;i++){
				
				if(i+1>=_packet_pointer){
					printf("%c",packet[i]);
				}
				else if(i%16==0)
					printf("\n");
				
				else
					printf("%02x ",packet[i]);

			}
			
			//printf("Total length : %d\n",ntohs(_ip->ip_len));

//			_input--;  
/*			
			if(_input <= 0){
				printf("_input : %d\n",_input);
				break;    // Count captured packedts and STOP.
			}
*/
			printf("\n");

		}
		else{
			printf("ck_packout wrong -1(Device down) or -2(EOF)\n");
			break;
		}
	}
	pcap_close(handle);
	return(0);
 }


	
// <netinet/if_ether.h>  : http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
// <netinet/ip.h>		 : http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
// <netinet/tcp.h> 		 : http://unix.superglobalmegacorp.com/BSD4.4Lite2/newsrc/netinet/tcp.h.html