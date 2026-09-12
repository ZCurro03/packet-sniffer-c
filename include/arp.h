#ifndef ARP_H
#define ARP_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define ARP_OPCODE_REQUEST   1  /* ARP Request operation code */
#define ARP_OPCODE_REPLY     2  /* ARP Reply operation code */
#define RARP_OPCODE_REQUEST  3  /* RARP Request operation code */
#define RARP_OPCODE_REPLY    4  /* RARP Reply operation code */
#define INARP_OPCODE_REQUEST 8  /* Inverse ARP Request operation code */
#define INARP_OPCODE_REPLY   9  /* Inverse ARP Reply operation code */

#define ARP_HW_TYPE_ETHERNET 1  /* Hardware type for Ethernet */

#define ARP_PROTO_TYPE_IPV4 0x0800  /* Protocol type for IPv4 */


/*******************
 * Data structures *
 *******************/

/**
 * ARP (Address Resolution Protocol) header format:
 * Hardware Type | Protocol Type | Hardware Address Length | Protocol Address Length | Operation Code
 * 
 * Hardware Type: 16 bits - Type of hardware (e.g., 1 for Ethernet)
 * Protocol Type: 16 bits - Type of protocol (e.g., 0x0800 for IPv4)
 * Hardware Address Length: 8 bits - Length of hardware address (MAC)
 * Protocol Address Length: 8 bits - Length of protocol address (IP)
 * Operation Code: 16 bits - Operation code (Request 1, Reply 2)
 */

/**
 * ARP header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the ARP header format.
 */
typedef struct __attribute__((packed)) {
    uint16_t hw_type;    /* Hardware type */
    uint16_t proto_type; /* Type of protocol */
    uint8_t  hlen;       /* Length of hardware address (MAC) */
    uint8_t  plen;       /* Length of protocol address (IP) */
    uint16_t opcode;     /* Operation code (Request 1, Reply 2, ...) */
} ArpBaseHeader;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Processes an ARP packet and prints relevant information.
 * @param packet Pointer to the raw ARP packet data.
 */
void process_arp_packet(const u_char *packet);

#endif /* ARP_H */
