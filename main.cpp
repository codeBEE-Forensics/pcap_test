#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <pcap.h>
#include "pcap_test.h"

void print_mac(uint8_t const* mac);
void print_ip(in_addr_t ip);
void print_port(uint16_t port);
void usage(void);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  const struct sniff_ethernet* ethernet;    /* Ther ethernet header */
  const struct sniff_ip* ip;                /* The IP header */
  const struct sniff_tcp* tcp;              /* The TCP header */
  const u_char* payload;                    /* Packet payload */

  uint32_t size_ip;
  uint32_t size_tcp;
  uint32_t size_payload;

  while (true) {
    struct pcap_pkthdr* header; /* time, packet length */
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    ethernet = (struct sniff_ethernet*)(packet);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) { /* Invalid IP header length */
        continue;
    }
    if (ip->ip_p != TCP_P_ID) { /* Is a TCP packet ? */
        continue;
    }

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) { /* Invalid TCP header length */
        continue;
    }

    printf("[TCP Segment Infomation]\n");

    printf("Destination Mac : ");
    print_mac(ethernet->ether_dhost);
    printf("Source Mac : ");
    print_mac(ethernet->ether_shost);

    printf("Source IP : ");
    print_ip(ip->ip_src.s_addr);
    printf("Destination IP : ");
    print_ip(ip->ip_dst.s_addr);

    printf("Source Port : ");
    print_port(tcp->th_sport);
    printf("Destination Port ");
    print_port(tcp->th_dport);

    size_payload = ntohs(ip->ip_len) - size_ip - size_tcp;
    if (size_payload == 0) {
        printf("Payload (max 10 bytes) : There is no payload\n\n");
    }
    else {
        payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        printf("Payload (Max 10 bytes) : ");
        for (int i = 0; i < 10; i++) {
            printf("%02X ", payload[i]);

            if (i == (size_payload - 1)) {
                break;
            }
        }
        printf("\n\n");
    }
  }

  pcap_close(handle);

  return 0;
}

void print_mac(uint8_t const* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(in_addr_t ip) {
    uint32_t haddr = ntohl(ip);
    printf("%u.%u.%u.%u\n", haddr>>24, (uint8_t)(haddr>>16), (uint8_t)(haddr>>8), (uint8_t)(haddr));
}

void print_port(uint16_t port) {
    printf("%u\n", ntohs(port));
}

void usage(void) {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
