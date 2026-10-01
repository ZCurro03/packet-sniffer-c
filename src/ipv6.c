#include <stdio.h>
#include "../include/utils.h"
#include "../include/ipv6.h"


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Processes the IPv6 headers and prints relevant information.
 * @param ipv6_header Pointer to the IPv6 header structure.
 * @param depth The depth of the current header in the encapsulation chain.
 */
void process_ipv6_headers(const IPv6Header *ipv6_header, uint8_t depth);


/***********************************
 * Public functions implementation *
 ***********************************/

void process_ipv6_packet(const u_char *packet, uint32_t length) {
    if (!packet || length < IPV6_HEADER_LEN) {
        fprintf(stderr, "Error: invalid IPv6 packet.\n");
        return;
    }

    const u_char *current_ptr = packet;
    uint32_t remaining_length = length;
    uint8_t next_header = IPV6_NEXT_HEADER_IPV6; 
    uint8_t depth = 0;

    /**
     * ARCHITECTURE & SECURITY DECISION:
     * ---------------------------------
     * IPv6 allows encapsulation (Next Header = 41), meaning an IPv6 packet can contain
     * another IPv6 packet inside it. To process this safely and prevent vulnerabilities:
     * 
     * 1. Iterative Flattening: We use a 'while' loop instead of recursion. This eliminates
     *    the risk of Stack Overflow (Stack Exhaustion) caused by deeply nested packets.
     * 2. Depth Limit (Chain Limit): We enforce a maximum encapsulation depth (MAX_IPV6_DEPTH).
     *    Processing more than a few nested headers is a well-known CPU exhaustion DoS attack vector.
     * 3. Bounds Checking: We strictly verify 'remaining_length' before casting memory to
     *    ensure we never read beyond the packet boundary.
     */
    while (next_header == IPV6_NEXT_HEADER_IPV6) {
        if (depth >= MAX_IPV6_DEPTH) {
            fprintf(stderr, "  [!] Security Warning: Maximum IPv6 nested depth exceeded. Dropping packet.\n");
            return;
        }

        if (remaining_length < IPV6_HEADER_LEN) {
            fprintf(stderr, "  [!] Error: Truncated nested IPv6 header.\n");
            return;
        }

        const IPv6Header *ipv6_header = (const IPv6Header *)current_ptr;
        process_ipv6_headers(ipv6_header, depth);

        /* Advance pointers and state for the next iteration */
        next_header = ipv6_header->next_header;
        current_ptr += IPV6_HEADER_LEN;
        remaining_length -= IPV6_HEADER_LEN;
        depth++;
    }

    switch (next_header) {
        case IPV6_NEXT_HEADER_TCP:
            fprintf(stdout, "TCP protocol to be implemented.\n");
            break;
        case IPV6_NEXT_HEADER_UDP:
            fprintf(stdout, "UDP protocol to be implemented.\n");
            break;
        case IPV6_NEXT_HEADER_ICMPV6:
            fprintf(stdout, "ICMPv6 protocol to be implemented.\n");
            break;
        default:
            fprintf(stdout, "Unknown or unsupported Next Header (0x%02X)\n", next_header);
            break;
    }
}


/************************************
 * Private functions implementation *
 ************************************/

void process_ipv6_headers(const IPv6Header *ipv6_header, uint8_t depth) {
    if (!ipv6_header || depth >= MAX_IPV6_DEPTH) {
        fprintf(stderr, "Error: invalid IPv6 header.\n");
        return;
    }

    uint32_t vtc_flow = ntohl(ipv6_header->version_tc_flow);
    uint8_t  version = (vtc_flow >> 28) & 0x0F;
    uint8_t  traffic_class = (vtc_flow >> 20) & 0xFF;
    uint32_t flow_label = vtc_flow & 0x0FFFFF;

    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->src_ip, src_ip_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ipv6_header->dest_ip, dst_ip_str, INET6_ADDRSTRLEN);

    if (depth > 0) {
        fprintf(stdout, "  Encapsulated IPv6 Header (Level %u):\n", depth);
    } else {
        fprintf(stdout, "IPv6 Header:\n");
    }

    int extra_indent = depth == 0 ? 0 : 2;
    int adjusted_width = depth == 0 ? FIELD_WIDTH : FIELD_WIDTH - 2;

    fprintf(stdout, "  %*s%-*s %u\n", extra_indent, "", adjusted_width, "Version:", version);
    fprintf(stdout, "  %*s%-*s 0x%02X\n", extra_indent, "", adjusted_width, "Traffic Class:", traffic_class);
    fprintf(stdout, "  %*s%-*s 0x%05X\n", extra_indent, "", adjusted_width, "Flow Label:", flow_label);
    fprintf(stdout, "  %*s%-*s %u bytes\n", extra_indent, "", adjusted_width, "Payload Length:", ntohs(ipv6_header->payload_length));
    fprintf(stdout, "  %*s%-*s %u\n", extra_indent, "", adjusted_width, "Hop Limit:", ipv6_header->hop_limit);
    fprintf(stdout, "  %*s%-*s %s\n", extra_indent, "", adjusted_width, "Source IP:", src_ip_str);
    fprintf(stdout, "  %*s%-*s %s\n", extra_indent, "", adjusted_width, "Destination IP:", dst_ip_str);
}
