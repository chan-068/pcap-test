#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

struct ethernet_hdr {
	uint8_t des_address[6];
	uint8_t src_address[6];
	uint16_t ethertype;
};

struct ip_hdr {
	uint8_t ver_IHL;
	uint8_t tos;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src_address[4];
	uint8_t des_address[4];
};

struct tcp_hdr{
	uint16_t scr_port;
	uint16_t des_port;
	uint32_t seq;
	uint32_t ack_num;
	uint8_t offset_reserved;
	uint8_t flag;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
};

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

void parse_packet(const u_char* packet){
	struct ethernet_hdr* eth_hdr = (struct ethernet_hdr *) packet;
	struct ip_hdr* ip = (struct ip_hdr *) (packet + 14);
	int protocol = ip->protocol;
	if(protocol!=6) return;
	int ip_len = (ip->ver_IHL&0x0F)*4;
	struct tcp_hdr* tcp = (struct tcp_hdr *)(packet + 14 + ip_len);
	int tcp_len = ((tcp->offset_reserved&0xF0)>>4)*4;

	printf("\n--------------------------\n");

	printf("\nMAC source address\n");
	for(int i=0; i<6; i++){
		printf("%02x ", eth_hdr->src_address[i]);
	}
	printf("\n");
	printf("MAC destination address\n");
	for(int i=0; i<6; i++){
		printf("%02x ", eth_hdr->des_address[i]);
	}
	printf("\n\n");
	printf("IP source address\n");
	for(int i=0; i<4; i++){
		printf("%d", ip->src_address[i]);
		if(i!=3) printf(".");
	}
	printf("\n");
	printf("IP destination address\n");
	for(int i=0; i<4; i++){
		printf("%d", ip->des_address[i]);
		if(i!=3) printf(".");
	}
	printf("\n\n");
	printf("TCP source port\n%d\n", tcp->scr_port);
	printf("TCP destination port\n%d\n\n", tcp->des_port);
	int data_len = ip->total_length - ip_len - tcp_len;
	int print_len = (data_len>20)? 20 : data_len;
	int i=0;
	if (data_len==0){
		printf("Data length is 0\n");
	}else{
		printf("DATA(up to 20 bytes)\n");
		while(i<print_len){
			printf("%02x ", *(packet+14+ip_len+tcp_len+i));
			i++;
		}
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

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		parse_packet(packet);
	}

	pcap_close(pcap);
}
