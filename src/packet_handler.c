#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../include/packet_handler.h"
#include "../include/ethernet.h"

#define TIMESTAMP_STR_SZ 16

void timestamp_to_str(struct timeval ts, char *buff, size_t sz) {
    if (!buff || sz < TIMESTAMP_STR_SZ) {
        memset(buff, 0, sz);
        return;
    }
    
    /* HH:MM:SS --> Hour, minute and second in local time */
    time_t local_tv_sec = ts.tv_sec;
    struct tm *local_time = localtime(&local_tv_sec);
    strftime(buff, sz, "%H:%M:%S", local_time);

    /* .mmmmmm --> microseconds (6 digits) */
    char microseconds[8] = {0};
    snprintf(microseconds, 8, ".%06d", (int)ts.tv_usec);
    strncat(buff, microseconds, 7);

    /* Final string: "HH:MM:SS.mmmmmm" */
    buff[TIMESTAMP_STR_SZ - 1] = '\0';
}

void process_ipv4_packet(const u_char *packet) {
    /* Placeholder for IPv4 packet processing logic */
    fprintf(stdout, "Processing IPv4 packet...\n");
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char timestamp[TIMESTAMP_STR_SZ] = {0};

    timestamp_to_str(header->ts, timestamp, sizeof(timestamp));

    fprintf(stdout, "[%s] Packet received (length: %d).\n", timestamp, header->len);

    EthernetHeader *eth_header = (EthernetHeader *)packet;
    fprintf(stdout, "Ethernet headers:\n");
    fprintf(stdout, "  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->dest_mac[0], eth_header->dest_mac[1], eth_header->dest_mac[2],
            eth_header->dest_mac[3], eth_header->dest_mac[4], eth_header->dest_mac[5]);
    fprintf(stdout, "  Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->src_mac[0], eth_header->src_mac[1], eth_header->src_mac[2],
            eth_header->src_mac[3], eth_header->src_mac[4], eth_header->src_mac[5]);

    uint16_t ethertype = ntohs(eth_header->ethertype);
    switch (ethertype) {
        case ETHERTYPE_IPv4:
            fprintf(stdout, "  EtherType:       IPv4 (0x%04x)\n", ethertype);
            process_ipv4_packet(packet + ETHERNET_HEADER_LEN);
            break;
        case ETHERTYPE_ARP:
            fprintf(stdout, "  EtherType:       ARP (0x%04x). To be implemented.\n", ethertype);
            break;
        case ETHERTYPE_IPv6:
            fprintf(stdout, "  EtherType:       IPv6 (0x%04x). To be implemented.\n", ethertype);
            break;
        default:
            fprintf(stdout, "  EtherType:       Unknown (0x%04x).\n", ethertype);
            break;
    }
}
