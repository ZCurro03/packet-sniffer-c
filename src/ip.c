#include <stdio.h>
#include "../include/ip.h"


uint8_t process_ipv4_headers(const IPv4Header *ipv4_header, uint8_t *header_len);


void process_ipv4_packet(const u_char *packet) {
    if (!packet) {
        fprintf(stderr, "Error: invalid IPv4 packet.\n");
        return;
    }

    const IPv4Header *ipv4_header = (const IPv4Header *)packet;

    uint8_t ipv4_header_len = 0;
    uint8_t protocol = process_ipv4_headers(ipv4_header, &ipv4_header_len);
    if (protocol == 0) {
        return;
    }

    switch (protocol) {
        case PROTOCOL_ICMP:
            fprintf(stdout, "  ICMP protocol to be implemented.\n");
            break;
        case PROTOCOL_TCP:
            fprintf(stdout, "  TCP protocol to be implemented.\n");
            break;
        case PROTOCOL_UDP:
            fprintf(stdout, "  UDP protocol to be implemented.\n");
            break;
        default:
            fprintf(stdout, "  Unknown protocol value.\n");
            break;
    }

    /* const u_char *transport_packet = packet + ipv4_header_len; */
}

uint8_t process_ipv4_headers(const IPv4Header *ipv4_header, uint8_t *header_len) {
    if (!ipv4_header || !header_len) {
        fprintf(stderr, "Error: invalid IPv4 header.\n");
        return 0;
    }

    uint8_t version = ipv4_header->version_ihl >> 4;
    uint8_t ihl = ipv4_header->version_ihl & 0x0F;
    *header_len = ihl * 4;  /* Real header size in bytes */

    /* Validate data */
    if (version != IPV4_VERSION || ihl < IPV4_MIN_IHL_VALUE || ihl > IPV4_MAX_IHL_VALUE) {
        fprintf(stderr, "Error: malformed IPv4 packet.\n");
        return 0;
    }

    fprintf(stdout, "IPv4 headers:\n");
    fprintf(stdout, "  Source IP:      %s\n", inet_ntoa(ipv4_header->src_ip));
    fprintf(stdout, "  Destination IP: %s\n", inet_ntoa(ipv4_header->dest_ip));

    uint8_t protocol = ipv4_header->protocol;
    switch (protocol) {
        case PROTOCOL_ICMP:
            fprintf(stdout, "  Protocol:       ICMP (%u).\n", protocol);
            break;
        case PROTOCOL_TCP:
            fprintf(stdout, "  Protocol:       TCP (%u).\n", protocol);
            break;
        case PROTOCOL_UDP:
            fprintf(stdout, "  Protocol:       UDP (%u).\n", protocol);
            break;
        default:
            fprintf(stdout, "  Protocol:       Unknown (%u).\n", protocol);
            break;
    }

    return protocol;
}
