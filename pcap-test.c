#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(struct libnet_ethernet_hdr* eth_hdr){
	printf("src mac : ");
        for(int i=0; i<ETHER_ADDR_LEN; i++){ 
		printf("%x",eth_hdr->ether_shost[i]);
                if(i == ETHER_ADDR_LEN - 1) break;
                printf(":");
        }
        printf("\n");

	printf("dst mac : ");
        for(int i=0; i<ETHER_ADDR_LEN; i++){ 
                printf("%x",eth_hdr->ether_dhost[i]);
                if(i == ETHER_ADDR_LEN - 1) break;
                printf(":");
        }
        printf("\n");	
}

void print_ip(struct libnet_ipv4_hdr* ip_hdr){
	uint32_t src_ip = ntohl(ip_hdr->ip_src.s_addr);
	printf("src ip : %d.%d.%d.%d\n",src_ip>>24, (src_ip>>16)&0xFF, (src_ip>>8)&0xFF, src_ip&0xFF);
	
	uint32_t dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
	printf("dst ip : %d.%d.%d.%d\n",dst_ip>>24, (dst_ip>>16)&0xFF, (dst_ip>>8)&0xFF, dst_ip&0xFF);	
}

void print_port(struct libnet_tcp_hdr* tcp_hdr){
	uint16_t src_port = ntohs(tcp_hdr->th_sport);
	printf("src port : %d\n", src_port);

	uint16_t dst_port = ntohs(tcp_hdr->th_dport);
	printf("dst port : %d\n", dst_port);
}

void print_data(char (*payload)[20]){
	printf("Payload(Data) : ");
	int i = 0;
	for(i=0; i<20; i++){
		if((*payload)[i] == 0){
			printf("None\n");
			return;
		}
	}
	
	for(i=0; i<20; i++){
		printf("%02x ", (*payload)[i]);
	}
	printf("\n");
}	

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	int packet_no = 0;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("packet No : %d\n", ++packet_no);
		printf("%u bytes captured\n", header->caplen);
		
		struct libnet_ethernet_hdr* eth_hdr = packet;
		print_mac(eth_hdr);
		
		struct libnet_ipv4_hdr* ip_hdr = packet + 14; // ethernet header : 14 bytes
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			print_ip(ip_hdr);
		}
		
		struct libnet_tcp_hdr* tcp_hdr = packet + 14 + 20; // ipv4 header : 20 bytes
		if(ip_hdr->ip_p == IPPROTO_TCP){
			print_port(tcp_hdr);
		}

		char (*payload)[20] = packet + 14 + 20 + 32; // tcp header : 32 bytes
		print_data(payload);

		printf("\n");
	}

	pcap_close(pcap);
}
