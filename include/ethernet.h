#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <pcap/pcap.h>

#define ETHERNET_ADDR_LEN   6  /* MAC addresses are 6 bytes long */
#define ETHERNET_HEADER_LEN 14 /* Ethernet header is 14 bytes long */

#define ETHERTYPE_IPv4 0x0800 /* IPv4 protocol */
#define ETHERTYPE_ARP  0x0806 /* ARP protocol */
#define ETHERTYPE_IPv6 0x86DD /* IPv6 protocol */

/** Ethernet II (or DIX) frame format:
 * Preamble | Destination MAC | Source MAC | EtherType | Payload | FCS
 * 
 * Preamble and FCS are ignored by libpcap, so final frame is:
 * Destination MAC | Source MAC | EtherType | Payload
 * 
 * Destination MAC: 48 bits (6 bytes) - MAC address of the destination device
 * Source MAC: 48 bits (6 bytes) - MAC address of the source device
 * EtherType: 16 bits (2 bytes) - Indicates the protocol of the payload (e.g., IPv4, ARP, IPv6)
 * Payload: Variable length - The actual data being transmitted (e.g., IP packet, ARP message)
 */

typedef struct __attribute__((__packed__)) {
    uint8_t  dest_mac[ETHERNET_ADDR_LEN]; /* Destination MAC address */
    uint8_t  src_mac[ETHERNET_ADDR_LEN];  /* Source MAC address */
    uint16_t ethertype;                   /* EtherType field (big-endian) */
} EthernetHeader;

void process_ethernet_frame(const u_char *packet);

#endif /* ETHERNET_H */
