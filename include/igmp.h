#ifndef IGMP_H
#define IGMP_H

#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define IGMP_TYPE_MEMBERSHIP_QUERY     0x11  /* Used in v1, v2 y v3 */
#define IGMP_TYPE_V1_MEMBERSHIP_REPORT 0x12  /* v1 Membership Report message type */
#define IGMP_TYPE_V2_MEMBERSHIP_REPORT 0x16  /* v2 Membership Report message type */
#define IGMP_TYPE_V2_LEAVE_GROUP       0x17  /* v2 Leave Group message type */
#define IGMP_TYPE_V3_MEMBERSHIP_REPORT 0x22  /* v3 Membership Report message type */

#define IGMP_V1V2_HEADER_LEN      8   /* Length of IGMP v1/v2 header in bytes */
#define IGMP_V3_REPORT_HEADER_LEN 8   /* Length of IGMP v3 Report header in bytes */
#define IGMP_V3_QUERY_HEADER_LEN  12  /* Length of IGMP v3 Query header in bytes */


/*******************
 * Data structures *
 *******************/

/**
 * IGMP v1/v2 header format:
 * Type | Max Resp Time | Checksum | Group Address
 * 
 * Type: 8 bits - The type of IGMP message (Membership Query, Membership Report, Leave Group)
 * Max Resp Time: 8 bits - The maximum response time for Membership Query messages (in tenths of a second)
 * Checksum: 16 bits - The checksum of the IGMP message
 * Group Address: 32 bits - The multicast group address (for Membership Report and Leave Group messages) or 0 (for Membership Query messages).
 */

/**
 * IGMP v1/v2 header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the IGMP v1/v2 header format. It also represents the first
 * 8 bytes of an IGMPv3 Query.
 */
typedef struct __attribute__((packed)) {
    uint8_t  type;           /* Message type */
    uint8_t  max_resp_time;  /* Maximum response time */
    uint16_t checksum;       /* Checksum */
    struct in_addr group;    /* Multicast group address */
} IgmpV1V2Header;

/**
 * IGMP v3 Query header format:
 * Type | Max Resp Code | Checksum | Group Address | Resv | S | QRV | QQIC | Number of Sources
 * 
 * Type: 8 bits - The type of IGMP message (Membership Query)
 * Max Resp Code: 8 bits - The maximum response code for Membership Query messages (in tenths of a second)
 * Checksum: 16 bits - The checksum of the IGMP message
 * Group Address: 32 bits - The multicast group address (for Membership Query messages)
 * Resv: 4 bits - Reserved for future use, should be set to zero
 * S: 1 bit - Suppression flag (0 = no suppression, 1 = suppression)
 * QRV: 3 bits - Querier's Robustness Variable
 * QQIC: 8 bits - Querier's Query Interval Code
 * Number of Sources: 16 bits - The number of source addresses that follow the header
 */

/**
 * IGMP v3 Query header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the IGMP v3 Query header format.
 * This structure represents the first 12 bytes of an IGMPv3 Query message.
 */
typedef struct __attribute__((packed)) {
    uint8_t  type;           /* Message type */
    uint8_t  max_resp_code;  /* Max Response Code */
    uint16_t checksum;       /* Checksum */
    struct in_addr group;    /* Multicast group address */
    uint8_t  resv_s_qrv;     /* Reserved (4 bits), Suppression (S, 1 bit) and QRV (3 bits) */
    uint8_t  qqic;           /* Querier's Query Interval Code */
    uint16_t num_sources;    /* Number of source addresses that follow the header */
} IgmpV3QueryHeader;

/**
 * IGMP v3 Report header format:
 * Type | Reserved1 | Checksum | Reserved2 | Number of Group Records
 * 
 * Type: 8 bits - The type of IGMP message (Membership Report)
 * Reserved1: 8 bits - Reserved for future use, should be set to zero
 * Checksum: 16 bits - The checksum of the IGMP message
 * Reserved2: 16 bits - Reserved for future use, should be set to zero
 * Number of Group Records: 16 bits - The number of group records that follow the header
 */

/**
 * IGMP v3 Report header structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the IGMP v3 Report header format.
 * This structure represents the first 8 bytes of an IGMPv3 Report message.
 */
typedef struct __attribute__((packed)) {
    uint8_t  type;           /* Message type */
    uint8_t  reserved1;      /* Reserved for future use, should be set to zero */
    uint16_t checksum;       /* Checksum */
    uint16_t reserved2;      /* Reserved for future use, should be set to zero */
    uint16_t num_records;    /* Number of group records that follow the header */
} IgmpV3ReportHeader;

/**
 * IGMP v3 Group Record format:
 * Record Type | Aux Data Len | Number of Sources | Multicast Address
 * 
 * Record Type: 8 bits - The type of group record (MODE_IS_INCLUDE, MODE_IS_EXCLUDE, CHANGE_TO_INCLUDE_MODE, CHANGE_TO_EXCLUDE_MODE, ALLOW_NEW_SOURCES, BLOCK_OLD_SOURCES)
 * Aux Data Len: 8 bits - The length of auxiliary data (in 32-bit words)
 * Number of Sources: 16 bits - The number of source addresses that follow the group record header
 * Multicast Address: 32 bits - The multicast group address for the group record
 */

/**
 * IGMP v3 Group Record structure definition.
 * The structure is packed to ensure that there is no padding between fields.
 * The fields are defined according to the IGMP v3 Group Record format.
 * This structure represents a single group record within an IGMPv3 Membership Report.
 */
typedef struct __attribute__((packed)) {
    uint8_t  record_type;           /* Record type */
    uint8_t  aux_data_len;          /* Auxiliary data length (in 32-bit words) */
    uint16_t num_sources;           /* Number of source addresses */
    struct in_addr multicast_addr;  /* The multicast group address */
} IgmpV3GroupRecord;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Process an IGMP packet.
 * @param packet The IGMP packet to process.
 * @param length The length of the IGMP packet.
 */
void process_igmp_packet(const u_char *packet, uint16_t length);

#endif /* IGMP_H */
