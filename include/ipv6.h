#ifndef IPV6_H
#define IPV6_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define IPV6_HEADER_LEN 40  /* Fixed length of the IPv6 base header */

#define IPV6_NEXT_HEADER_HOP_BY_HOP 0   /* Hop-by-Hop Options */
#define IPV6_NEXT_HEADER_TCP        6   /* TCP Next Header value */
#define IPV6_NEXT_HEADER_UDP        17  /* UDP Next Header value */
#define IPV6_NEXT_HEADER_IPV6       41  /* IPv6 Encapsulation */
#define IPV6_NEXT_HEADER_ICMPV6     58  /* ICMPv6 Next Header value */

#define MAX_IPV6_DEPTH 4    /* Maximum allowed nested IPv6 headers to prevent DoS */


/*******************
 * Data structures *
 *******************/

/**
 * IPv6 header format:
 * Version | Traffic Class | Flow Label | Payload Length | Next Header | Hop Limit | Source Address | Destination Address
 * 
 * Version: 4 bits - IP version (6 for IPv6)
 * Traffic Class: 8 bits - Quality of service
 * Flow Label: 20 bits - Used for labeling packets belonging to the same flow
 * Payload Length: 16 bits - Length of the payload (excluding the IPv6 header)
 * Next Header: 8 bits - Type of the next header (TCP, UDP, ICMPv6, etc.)
 * Hop Limit: 8 bits - Maximum number of hops the packet can traverse
 * Source Address: 128 bits - Source IPv6 Address
 * Destination Address: 128 bits - Destination IPv6 Address
 */

/**
 * Ipv6 header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the IPv6 header format.
 */
typedef struct __attribute__((packed)) {
    uint32_t version_tc_flow;   /* Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits) */
    uint16_t payload_length;    /* Length of the payload (excluding the IPv6 header) */
    uint8_t  next_header;       /* Next header type (TCP, UDP, ICMPv6, etc.) */
    uint8_t  hop_limit;         /* Maximum number of hops the packet can traverse */
    struct in6_addr src_ip;     /* Source IPv6 Address */
    struct in6_addr dest_ip;    /* Destination IPv6 Address */
} IPv6Header;

/********************************
 * Public functions declaration *
 ********************************/

/**
 * Processes an IPv6 packet and prints relevant information.
 * @param packet Pointer to the raw packet data.
 * @param length The length of the IPv6 packet.
 */
void process_ipv6_packet(const u_char *packet, uint32_t length);

#endif /* IPV6_H */