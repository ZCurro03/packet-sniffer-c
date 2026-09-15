#ifndef TCP_H
#define TCP_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define TCP_NUM_FLAGS 8     /* Number of TCP flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN) */
#define TCP_FLAG_CWR  0x80  /* CWR flag mask */
#define TCP_FLAG_ECE  0x40  /* ECE flag mask */
#define TCP_FLAG_URG  0x20  /* URG flag mask */
#define TCP_FLAG_ACK  0x10  /* ACK flag mask */
#define TCP_FLAG_PSH  0x08  /* PSH flag mask */
#define TCP_FLAG_RST  0x04  /* RST flag mask */
#define TCP_FLAG_SYN  0x02  /* SYN flag mask */
#define TCP_FLAG_FIN  0x01  /* FIN flag mask */


/*******************
 * Data structures *
 *******************/

/**
 * TCP header format:
 * Source Port | Destination Port | Sequence Number | Acknowledgment Number | Data Offset | Reserved | Flags | Window Size | Checksum | Urgent Pointer
 * 
 * Source Port: 16 bits - The port number of the sender
 * Destination Port: 16 bits - The port number of the receiver
 * Sequence Number: 32 bits - The sequence number of the first byte in this segment
 * Acknowledgment Number: 32 bits - The next sequence number that the sender of the acknowledgment expects to receive
 * Data Offset: 4 bits - The size of the TCP header in 32-bit words
 * Reserved: 4 bits - Reserved for future use, should be set to zero
 * Flags: 8 bits - Control flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
 * Window Size: 16 bits - The size of the receive window, which specifies the number of bytes that the sender is willing to receive
 * Checksum: 16 bits - The checksum of the TCP header and data
 * Urgent Pointer: 16 bits - If the URG flag is set, this field points to the last urgent byte in the packet
 */

/**
 * TCP header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the TCP header format.
 */
typedef struct __attribute__((packed)) {
    uint16_t src_port;    /* Source Port (16 bits) */
    uint16_t dest_port;   /* Destination Port (16 bits) */
    uint32_t seq_num;     /* Sequence Number (32 bits) */
    uint32_t ack_num;     /* Acknowledgment Number (32 bits) */
    uint8_t  offset_res;  /* Data Offset (4 bits) and Reserved (4 bits) */
    uint8_t  flags;       /* Control Flags (8 bits: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN) */
    uint16_t window;      /* Window Size (16 bits) */
    uint16_t checksum;    /* Checksum (16 bits) */
    uint16_t urg_ptr;     /* Urgent Pointer (16 bits) */
} TcpHeader;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Process a TCP segment.
 * @param segment The TCP segment to process.
 */
void process_tcp_segment(const u_char *segment);

#endif /* TCP_H */
