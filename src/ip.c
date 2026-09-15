#include <stdio.h>
#include "../include/utils.h"
#include "../include/ip.h"
#include "../include/tcp.h"
#include "../include/udp.h"
#include "../include/icmp.h"


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Processes the IPv4 headers and prints relevant information.
 * @param ipv4_header Pointer to the IPv4 header structure.
 * @param header_len Pointer to a variable where the calculated header length will be stored.
 * @return The protocol number of the next layer (TCP, UDP, ICMP...) or 0 if an error occurred.
 */
uint8_t process_ipv4_headers(const IPv4Header *ipv4_header, uint8_t *header_len);


/***********************************
 * Public functions implementation *
 ***********************************/

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
            process_icmp_message(packet + ipv4_header_len);
            break;
        case PROTOCOL_IGMP:
            fprintf(stdout, "IGMP to be implemented.\n");
            break;
        case PROTOCOL_TCP:
            process_tcp_segment(packet + ipv4_header_len);
            break;
        case PROTOCOL_UDP:
            process_udp_datagram(packet + ipv4_header_len);
            break;
        default:
            fprintf(stdout, "Unsupported protocol value.\n");
            break;
    }

    /* const u_char *transport_packet = packet + ipv4_header_len; */
}


/************************************
 * Private functions implementation *
 ************************************/

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
    fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Source IP:", inet_ntoa(ipv4_header->src_ip));
    fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Destination IP:", inet_ntoa(ipv4_header->dest_ip));

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Protocol:");
    uint8_t protocol = ipv4_header->protocol;
    switch (protocol) {
        case PROTOCOL_ICMP:
            fprintf(stdout, "ICMP");
            break;
        case PROTOCOL_TCP:
            fprintf(stdout, "TCP");
            break;
        case PROTOCOL_UDP:
            fprintf(stdout, "UDP");
            break;
        default:
            fprintf(stdout, "Other");
            break;
    }
    fprintf(stdout, " (%u)\n", protocol);

    return protocol;
}
