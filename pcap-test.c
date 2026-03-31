#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define LIBNET_LIL_ENDIAN 1
#define ETHER_ADDR_LEN 6
#define FDDI_ADDR_LEN 6
#define TOKEN_RING_ADDR_LEN 6
#define LIBNET_ORG_CODE_SIZE 3

typedef uint32_t n_time;


#include "libnet-headers.h"

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

void print_mac(const uint8_t* mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const struct in_addr* addr) {
    uint32_t ip = ntohl(addr->s_addr);
    printf("%u.%u.%u.%u",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff);
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

		if (header->caplen < LIBNET_ETH_H) continue;

		const struct libnet_ethernet_hdr* eth =
			(const struct libnet_ethernet_hdr*)packet;

		if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

		if (header->caplen < LIBNET_ETH_H + LIBNET_IPV4_H) continue;

		const struct libnet_ipv4_hdr* ip =
			(const struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);

		if (ip->ip_v != 4) continue;
		if (ip->ip_p != IPPROTO_TCP) continue;

		uint32_t ip_header_len = ip->ip_hl * 4;
		if (ip_header_len < LIBNET_IPV4_H) continue;
		if (header->caplen < LIBNET_ETH_H + ip_header_len + LIBNET_TCP_H) continue;

		const struct libnet_tcp_hdr* tcp = (const struct libnet_tcp_hdr*)((const u_char*)ip + ip_header_len);

		uint32_t tcp_header_len = tcp->th_off * 4;
		if (tcp_header_len < LIBNET_TCP_H) continue;
		if (header->caplen < LIBNET_ETH_H + ip_header_len + tcp_header_len) continue;

		const u_char* payload = (const u_char*)tcp + tcp_header_len;
		uint32_t payload_len = header->caplen - (LIBNET_ETH_H + ip_header_len + tcp_header_len);
		uint32_t dump_len = payload_len > 20 ? 20 : payload_len;
                

                printf("%u bytes captured\n", header->caplen);
		printf("Ethernet Header\n");
		printf("src mac:");
                print_mac(eth->ether_shost);
                printf("\n");		
                printf("dst mac:");
		print_mac(eth->ether_dhost);
		printf("\n");

		printf("IP Header\n");
		printf("src ip:");
		print_ip(&ip->ip_src);
		printf("\n");
		printf("dst ip:");
		print_ip(&ip->ip_dst);
		printf("\n");

		printf("TCP Header\n");
		printf("src port: %u\n", ntohs(tcp->th_sport));
		printf("dst port: %u\n", ntohs(tcp->th_dport));

		printf("Payload\n");
		printf("data:");
		for (uint32_t i = 0; i < dump_len; i++) {
			printf(" %02x", payload[i]);
		}
		printf("\n\n");
	}

	pcap_close(pcap);
	return 0;
}
