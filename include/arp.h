#ifndef ARP_H
#define ARP_H

#include <pcap/pcap.h>

#define ARP_OPCODE_REQUEST 1    /* ARP request operation code */
#define ARP_OPCODE_REPLY   2    /* ARP reply operation code */

#define ARP_HW_TYPE_ETHERNET 1  /* Hardware type for Ethernet */

#define ARP_PROTO_TYPE_IPV4 0x0800  /* Protocol type for IPv4 */

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

typedef struct __attribute__((packed)) {
    uint16_t hw_type;    /* Hardware type */
    uint16_t proto_type; /* Type of protocol */
    uint8_t  hlen;       /* Length of hardware address (MAC) */
    uint8_t  plen;       /* Length of protocol address (IP) */
    uint16_t opcode;     /* Operation code (Request 1, Reply 2) */
} ArpBaseHeader;

void process_arp_packet(const u_char *packet);

#endif /* ARP_H */