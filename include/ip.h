#ifndef IP_H
#define IP_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define IPV4_ADDR_LEN 4     /* Length of an IPv4 address in bytes */

#define IPV4_MIN_IHL_VALUE 5    /* Minimum IHL value for IPv4 header (5 * 4 = 20 bytes) */
#define IPV4_MAX_IHL_VALUE 15   /* Maximum IHL value for IPv4 header (15 * 4 = 60 bytes) */

#define IPV4_VERSION 4  /* IPv4 version number in the IP header */

#define PROTOCOL_ICMP 1     /* ICMP protocol number in the IP header */
#define PROTOCOL_TCP  6     /* TCP protocol number in the IP header */
#define PROTOCOL_UDP  17    /* UDP protocol number in the IP header */


/*******************
 * Data structures *
 *******************/

/** IPv4 header format:
 * Version | IHL | Type of Service | Total Length | Identification | Flags | Fragment Offset | TTL | Protocol | Header Checksum | Source IP | Destination IP
 * 
 * Version: 4 bits - IP version (4 for IPv4)
 * IHL: 4 bits - Internet Header Length (in 32-bit words)
 * Type of Service: 8 bits - Quality of service
 * Total Length: 16 bits - Total length of the packet (IP header + payload)
 * Identification: 16 bits - Unique identifier for the packet
 * Flags: 3 bits - Control flags
 * Fragment Offset: 13 bits - Offset of the fragment in the original packet
 * TTL: 8 bits - Time to Live
 * Protocol: 8 bits - Protocol of the next layer (TCP, UDP, ICMP...)
 * Header Checksum: 16 bits - Checksum of the IP header
 * Source IP: 32 bits - Source IP Address
 * Destination IP: 32 bits - Destination IP Address
 * 
 * Options field is optional and not included in this structure. The header without options is 20 bytes long.
 */

/**
 * IPv4 header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the IPv4 header format. The Options field is not included in
 * this structure, and the header length is determined by the IHL field.
 */
typedef struct __attribute__((packed)) {
    uint8_t  version_ihl;       /* Version (4 bits) + Internet Header Length (4 bits) */
    uint8_t  tos;               /* Type of Service */
    uint16_t total_length;      /* Total length of the packet (IP header + payload) */
    uint16_t id;                /* Identification */
    uint16_t flags_fo;          /* Flags (3 bits) + Fragment offset (13 bits) */
    uint8_t  ttl;               /* Time to Live */
    uint8_t  protocol;          /* Protocol of the next layer (TCP, UDP, ICMP...) */
    uint16_t checksum;          /* Header Checksum */
    struct in_addr src_ip;      /* Source IP Address (32 bits) */
    struct in_addr dest_ip;     /* Destination IP Address (32 bits) */
} IPv4Header;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Processes an IPv4 packet and prints relevant information.
 * @param packet Pointer to the raw packet data.
 */
void process_ipv4_packet(const u_char *packet);

#endif /* IP_H */
