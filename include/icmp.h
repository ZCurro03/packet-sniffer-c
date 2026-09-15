#ifndef ICMP_H
#define ICMP_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define ICMP_TYPE_ECHO_REPLY    0   /* Echo Reply */
#define ICMP_TYPE_DEST_UNREACH  3   /* Destination Unreachable */
#define ICMP_TYPE_ECHO_REQUEST  8   /* Echo Request */
#define ICMP_TYPE_TIME_EXCEEDED 11  /* Time Exceeded */


/*******************
 * Data structures *
 *******************/

/**
 * ICMP header format:
 * Type | Code | Checksum | Rest of Header (varies based on Type and Code)
 * 
 * Type: 8 bits - The type of the ICMP message (e.g., Echo Request, Echo Reply)
 * Code: 8 bits - The code for the ICMP message, providing additional context for the type
 * Checksum: 16 bits - The checksum of the ICMP message, used for error-checking
 * Rest of Header: 32 bits - Varies based on the Type and Code of the ICMP message. For Echo Request and Echo Reply, it contains an Identifier and Sequence Number.
 */

/**
 * ICMP header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the ICMP header format. The Rest of Header field is
 * represented as two 16-bit fields (Identifier and Sequence Number) for Echo Request and
 * Echo Reply messages.
 */
typedef struct __attribute__((packed)) {
    uint8_t  type;        /* Message type */
    uint8_t  code;        /* Message code */
    uint16_t checksum;    /* Checksum */
    uint16_t identifier;  /* Identifier */
    uint16_t sequence;    /* Sequence Number */
} IcmpHeader;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Process an ICMP message.
 * @param message The raw ICMP message to process.
 */
void process_icmp_message(const u_char *message);

#endif /* ICMP_H */
