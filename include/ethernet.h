#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define ETHERNET_ADDR_LEN   6  /* Length of a MAC address in bytes */
#define ETHERNET_HEADER_LEN 14 /* Length of an Ethernet header in bytes */

#define ETHERTYPE_IPv4 0x0800 /* IPv4 ethertype value */
#define ETHERTYPE_ARP  0x0806 /* ARP ethertype value */
#define ETHERTYPE_IPv6 0x86DD /* IPv6 ethertype value */


/*******************
 * Data structures *
 *******************/

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

/**
 * Ethernet header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the Ethernet II header format.
 */
typedef struct __attribute__((__packed__)) {
    uint8_t  dest_mac[ETHERNET_ADDR_LEN]; /* Destination MAC address */
    uint8_t  src_mac[ETHERNET_ADDR_LEN];  /* Source MAC address */
    uint16_t ethertype;                   /* EtherType field (big-endian) */
} EthernetHeader;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Processes an Ethernet frame and prints relevant information.
 * @param packet Pointer to the raw Ethernet frame data.
 */
void process_ethernet_frame(const u_char *packet);

#endif /* ETHERNET_H */
