#ifndef ICMPV6_H
#define ICMPV6_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define ICMPV6_HEADER_LEN 4                 /* Length of an ICMPv6 header in bytes */

/* ICMPv6 Error Messages */
#define ICMPV6_TYPE_DEST_UNREACH   1        /* Destination Unreachable */
#define ICMPV6_TYPE_PACKET_TOO_BIG 2        /* Packet Too Big */
#define ICMPV6_TYPE_TIME_EXCEEDED  3        /* Time Exceeded */
#define ICMPV6_TYPE_PARAM_PROBLEM  4        /* Parameter Problem */

/* ICMPv6 Informational Messages */
#define ICMPV6_TYPE_ECHO_REQUEST   128      /* Echo Request (Ping6) */
#define ICMPV6_TYPE_ECHO_REPLY     129      /* Echo Reply (Ping6) */

/* Neighbor Discovery Protocol (NDP) Messages */
#define ICMPV6_TYPE_ROUTER_SOL     133      /* Router Solicitation */
#define ICMPV6_TYPE_ROUTER_ADV     134      /* Router Advertisement */
#define ICMPV6_TYPE_NEIGHBOR_SOL   135      /* Neighbor Solicitation */
#define ICMPV6_TYPE_NEIGHBOR_ADV   136      /* Neighbor Advertisement */
#define ICMPV6_TYPE_REDIRECT       137      /* Redirect Message */

/* Inverse Neighbor Discovery (IND) Messages */
#define ICMPV6_TYPE_INV_NEIGHBOR_SOL 141    /* Inverse Neighbor Solicitation */
#define ICMPV6_TYPE_INV_NEIGHBOR_ADV 142    /* Inverse Neighbor Advertisement */


/*******************
 * Data structures *
 *******************/

/**
 * ICMPv6 header format:
 * Type | Code | Checksum | Content (varies based on Type and Code)
 * 
 * Type: 8 bits - The type of the ICMPv6 message (e.g., Echo Request, Echo Reply)
 * Code: 8 bits - The code for the ICMPv6 message, providing additional context for the type
 * Checksum: 16 bits - The checksum of the ICMPv6 message, used for error-checking
 * Content: variable size - Varies based on the Type and Code of the ICMPv6 message.
 */

/**
 * ICMPv6 header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the ICMPv6 header format.
 */
typedef struct __attribute__((packed)) {
    uint8_t  type;        /* Message type */
    uint8_t  code;        /* Message code */
    uint16_t checksum;    /* Checksum */
} Icmpv6Header;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Processes an ICMPv6 message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 */
void process_icmpv6_message(const u_char *message, uint32_t length);

#endif /* ICMPV6_H */
