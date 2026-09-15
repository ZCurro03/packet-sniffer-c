#ifndef UDP_H
#define UDP_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/


/*******************
 * Data structures *
 *******************/

/**
 * UDP header format:
 * Source Port | Destination Port | Length | Checksum
 * 
 * Source Port: 16 bits - The port number of the sender
 * Destination Port: 16 bits - The port number of the receiver
 * Length: 16 bits - The length of the UDP header and data
 * Checksum: 16 bits - The checksum of the UDP header and data
 */

/**
 * UDP header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the UDP header format.
 */
typedef struct __attribute__((packed)) {
    uint16_t src_port;    /* Source Port (16 bits) */
    uint16_t dest_port;   /* Destination Port (16 bits) */
    uint16_t len;         /* Length (16 bits) */
    uint16_t checksum;    /* Checksum (16 bits) */
} UdpHeader;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Process a UDP datagram.
 * @param datagram The UDP datagram to process.
 */
void process_udp_datagram(const u_char *datagram);

#endif /* UDP_H */
