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

/**
 * ICMPv6 message content structures for specific message types.
 * These structures are used to interpret the content of ICMPv6 messages based on their type and code.
 * The fields are defined according to the ICMPv6 message content format.
 * 
 * - Destination Unreachable and Time Exceeded: 32 unused bits.
 * - Packet Too Big: 32 bits for the MTU value.
 * - Parameter Problem: 32 bits for the pointer to the error.
 * - Echo Request and Echo Reply: 16 bits for the identifier and 16 bits for the sequence number.
 * - Router Advertisement: 8 bits for the current hop limit, 8 bits for flags, 16 bits for the router lifetime, 32
 *   bits for the reachable time, and 32 bits for the retransmission timer.
 * - Neighbor Solicitation: 32 reserved bits and 128 bits for the target address.
 * - Neighbor Advertisement: 32 bits for flags and 128 bits for the target address.
 * - Redirect Message: 32 reserved bits, 128 bits for the target address, and 128 bits for the destination address.
 */

/**
 * Structure for ICMPv6 messages that have 32 reserved or unused bits.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint32_t reserved;
} Icmpv6Reserved4;

/**
 * Structure for ICMPv6 Packet Too Big messages, which include a 32-bit MTU value.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint32_t mtu;
} Icmpv6ErrorMtu;

/**
 * Structure for ICMPv6 Parameter Problem messages, which include a 32-bit pointer to the error.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint32_t pointer;
} Icmpv6ErrorPointer;

/**
 * Structure for ICMPv6 Echo Request and Echo Reply messages, which include a 16-bit identifier and a 16-bit sequence number.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint16_t identifier;
    uint16_t sequence;
} Icmpv6EchoFields;

/**
 * Structure for ICMPv6 Router Advertisement messages, which include various fields related to the router's configuration.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint8_t  cur_hop_limit;
    uint8_t  flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
} Icmpv6NdRouterAdv;

/**
 * Structure for ICMPv6 Neighbor Solicitation messages, which include a 32-bit reserved field and a 128-bit target address.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint32_t reserved;
    uint8_t  target_addr[16];
} Icmpv6NdNeighborSol;

/**
 * Structure for ICMPv6 Neighbor Advertisement messages, which include a 32-bit flags field and a 128-bit target address.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint32_t flags;
    uint8_t  target_addr[16];
} Icmpv6NdNeighborAdv;

/**
 * Structure for ICMPv6 Redirect messages, which include a 32-bit reserved field, a 128-bit target address, and a 128-bit
 * destination address.
 * The structure is packed to ensure that there is no padding between fields.
 */
typedef struct __attribute__((packed)) {
    uint32_t reserved;
    uint8_t  target_addr[16];
    uint8_t  dest_addr[16];
} Icmpv6NdRedirect;


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
