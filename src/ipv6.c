#include <stdio.h>
#include "../include/utils.h"
#include "../include/ipv6.h"
#include "../include/tcp.h"
#include "../include/udp.h"


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
        fprintf(stderr, "Error: invalid or truncated IPv6 packet.\n");
        return;
    }

    const u_char *current_ptr = packet;
    uint32_t remaining_length = length;
    uint32_t expected_payload_len = 0;
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
            fprintf(stderr, "  [!] Warning: maximum IPv6 nested depth exceeded. Dropping packet.\n");
            return;
        }

        if (remaining_length < IPV6_HEADER_LEN) {
            fprintf(stderr, "  [!] Warning: truncated nested IPv6 header.\n");
            return;
        }

        const IPv6Header *ipv6_header = (const IPv6Header *)current_ptr;
        uint8_t version = (ntohl(ipv6_header->version_tc_flow) >> 28) & 0x0F;
        if (version != IPV6_VERSION) {
            fprintf(stderr, "Error: malformed IPv6 header (version %u != %u).\n", version, IPV6_VERSION);
            return;
        }

        expected_payload_len = ntohs(ipv6_header->payload_length);
        process_ipv6_headers(ipv6_header, depth);

        /* Advance pointers and state for the next iteration */
        next_header = ipv6_header->next_header;
        current_ptr += IPV6_HEADER_LEN;
        remaining_length -= IPV6_HEADER_LEN;
        depth++;
    }

    uint32_t captured_payload_len = remaining_length;
    uint32_t safe_payload_len = expected_payload_len;

    if (expected_payload_len > captured_payload_len) {
        fprintf(stdout, "  [!] Warning: IPv6 payload may have been truncated during capture (%u of %u bytes available).\n",
                captured_payload_len, expected_payload_len);
        safe_payload_len = captured_payload_len;
    }

    (void)safe_payload_len;  /* Suppress unused variable warning */

    switch (next_header) {
        case IPV6_NEXT_HEADER_TCP:
            process_tcp_segment(current_ptr, safe_payload_len);
            break;
        case IPV6_NEXT_HEADER_UDP:
            process_udp_datagram(current_ptr, safe_payload_len);
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
    uint8_t  hop_limit = ipv6_header->hop_limit;
    uint16_t payload_length = ntohs(ipv6_header->payload_length);

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
    fprintf(stdout, "  %*s%-*s %u bytes\n", extra_indent, "", adjusted_width, "Payload Length:", payload_length);
    fprintf(stdout, "  %*s%-*s %u\n", extra_indent, "", adjusted_width, "Hop Limit:", hop_limit);
    fprintf(stdout, "  %*s%-*s %s\n", extra_indent, "", adjusted_width, "Source IP:", src_ip_str);
    fprintf(stdout, "  %*s%-*s %s\n", extra_indent, "", adjusted_width, "Destination IP:", dst_ip_str);
}
