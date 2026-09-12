#include <stdio.h>
#include "../include/utils.h"
#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/arp.h"


uint16_t process_ethernet_headers(const EthernetHeader *eth_header);


void process_ethernet_frame(const u_char *packet) {
    if (!packet) {
        fprintf(stderr, "Error: invalid Ethernet frame.\n");
        return;
    }

    const EthernetHeader *eth_header = (const EthernetHeader *)packet;

    uint16_t ethertype = process_ethernet_headers(eth_header);
    if (ethertype == 0) {
        fprintf(stderr, "Error: unable to process Ethernet headers.\n");
        return;
    }

    switch (ethertype) {
        case ETHERTYPE_IPv4:
            process_ipv4_packet(packet + ETHERNET_HEADER_LEN);
            break;
        case ETHERTYPE_ARP:
            process_arp_packet(packet + ETHERNET_HEADER_LEN);
            break;
        case ETHERTYPE_IPv6:
            fprintf(stdout, "IPv6 protocol to be implemented.\n");
            break;
        default:
            fprintf(stdout, "Unsupported upper-layer protocol.\n");
            break;
    }
}

uint16_t process_ethernet_headers(const EthernetHeader *eth_header) {
    if (!eth_header) {
        return 0;
    }

    fprintf(stdout, "Ethernet headers:\n");
    fprintf(stdout, "  %-*s %02X:%02X:%02X:%02X:%02X:%02X\n",
            FIELD_WIDTH, "Destination MAC:",
            eth_header->dest_mac[0], eth_header->dest_mac[1], eth_header->dest_mac[2],
            eth_header->dest_mac[3], eth_header->dest_mac[4], eth_header->dest_mac[5]);
    fprintf(stdout, "  %-*s %02X:%02X:%02X:%02X:%02X:%02X\n",
            FIELD_WIDTH, "Source MAC:",
            eth_header->src_mac[0], eth_header->src_mac[1], eth_header->src_mac[2],
            eth_header->src_mac[3], eth_header->src_mac[4], eth_header->src_mac[5]);

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "EtherType:");
    uint16_t ethertype = ntohs(eth_header->ethertype);
    switch (ethertype) {
        case ETHERTYPE_IPv4:
            fprintf(stdout, "IPv4 (0x%04X)\n", ethertype);
            break;
        case ETHERTYPE_ARP:
            fprintf(stdout, "ARP (0x%04X)\n", ethertype);
            break;
        case ETHERTYPE_IPv6:
            fprintf(stdout, "IPv6 (0x%04X)\n", ethertype);
            break;
        default:
            fprintf(stdout, "Other (0x%04X)\n", ethertype);
            break;
    }

    return ethertype;
}
