#include <stdio.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/igmp.h"


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Processes an IGMP v1/v2 packet and prints relevant information.
 * @param packet Pointer to the IGMP v1/v2 packet.
 * @param length Length of the IGMP v1/v2 packet.
 */
void process_igmp_v1v2_packet(const u_char *packet, uint16_t length);

/**
 * Processes an IGMP v3 Report packet and prints relevant information.
 * @param packet Pointer to the IGMP v3 packet.
 * @param length Length of the IGMP v3 packet.
 */
void process_igmp_v3_report(const u_char *packet, uint16_t length);

/**
 * Processes an IGMP v3 Query packet and prints relevant information.
 * @param packet Pointer to the IGMP v3 packet.
 * @param length Length of the IGMP v3 packet.
 */
void process_igmp_v3_query(const u_char *packet, uint16_t length);


/***********************************
 * Public functions implementation *
 ***********************************/

void process_igmp_packet(const u_char *packet, uint16_t length) {
    if (!packet || length < IGMP_V1V2_HEADER_LEN) {
        fprintf(stderr, "Error: invalid IGMP packet.\n");
        return;
    }

    uint8_t igmp_type = packet[0];

    fprintf(stdout, "IGMP Message:\n");
    switch (igmp_type) {
        case IGMP_TYPE_MEMBERSHIP_QUERY:
            if (length >= IGMP_V3_QUERY_HEADER_LEN) {
                process_igmp_v3_query(packet, length);
            } else {
                process_igmp_v1v2_packet(packet, length);
            }
            break;
        case IGMP_TYPE_V1_MEMBERSHIP_REPORT:
        case IGMP_TYPE_V2_MEMBERSHIP_REPORT:
        case IGMP_TYPE_V2_LEAVE_GROUP:
            process_igmp_v1v2_packet(packet, length);
            break;
        case IGMP_TYPE_V3_MEMBERSHIP_REPORT:
            process_igmp_v3_report(packet, length);
            break;
        default:
            fprintf(stdout, "  %-*s Unknown (0x%02X)\n", FIELD_WIDTH, "Type:", igmp_type);
            break;
    }
}


/************************************
 * Private functions implementation *
 ************************************/

void process_igmp_v1v2_packet(const u_char *packet, uint16_t length) {
    if (!packet || length < IGMP_V1V2_HEADER_LEN) {
        fprintf(stderr, "Error: invalid IGMP v1/v2 packet.\n");
        return;
    }
    
    const IgmpV1V2Header *igmp_header = (const IgmpV1V2Header *)packet;

    uint8_t type          = igmp_header->type;
    uint8_t max_resp_time = igmp_header->max_resp_time;
    struct in_addr group  = igmp_header->group;

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Type:");
    switch (type) {
        case IGMP_TYPE_MEMBERSHIP_QUERY:
            fprintf(stdout, "v%s Membership Query", max_resp_time == 0 ? "1" : "2");
            break;
        case IGMP_TYPE_V1_MEMBERSHIP_REPORT:
            fprintf(stdout, "v1 Membership Report");
            break;
        case IGMP_TYPE_V2_MEMBERSHIP_REPORT:
            fprintf(stdout, "v2 Membership Report");
            break;
        case IGMP_TYPE_V2_LEAVE_GROUP:
            fprintf(stdout, "v2 Leave Group");
            break;
        default:
            fprintf(stdout, "Unknown");
            break;
    }
    fprintf(stdout, " (0x%02X)\n", type);

    /* In IGMP v2, max_resp_time is expressed in tenths of a second. In v1 it's 0. */
    if (type == IGMP_TYPE_MEMBERSHIP_QUERY && max_resp_time > 0) {
        fprintf(stdout, "  %-*s %u deciseconds\n", FIELD_WIDTH, "Max Response Time:", max_resp_time);
    }

    fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Group Address:", inet_ntoa(group));
}

void process_igmp_v3_report(const u_char *packet, uint16_t length) {
    if (!packet || length < IGMP_V3_REPORT_HEADER_LEN) {
        fprintf(stderr, "Error: invalid IGMP v3 Report packet.\n");
        return;
    }

    const IgmpV3ReportHeader *report = (const IgmpV3ReportHeader *)packet;
    uint16_t num_records = ntohs(report->num_records);

    fprintf(stdout, "  %-*s v3 Membership Report (0x22)\n", FIELD_WIDTH, "Type:");
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Group Records:", num_records);

    const u_char *packet_end = packet + length; /* Safety limit */
    const u_char *ptr = packet + sizeof(IgmpV3ReportHeader);

    for (uint16_t i = 0; i < num_records; i++) {
        if (ptr + sizeof(IgmpV3GroupRecord) > packet_end) {
            fprintf(stderr, "  [!] Warning: Truncated IGMPv3 Group Record.\n");
            break; 
        }

        const IgmpV3GroupRecord *record = (const IgmpV3GroupRecord *)ptr;
        uint16_t num_sources = ntohs(record->num_sources);

        fprintf(stdout, "  Record %u:\n", i + 1);
        fprintf(stdout, "    %-*s %u\n", FIELD_WIDTH - 2, "Record Type:", record->record_type);
        fprintf(stdout, "    %-*s %s\n", FIELD_WIDTH - 2, "Multicast IP:", inet_ntoa(record->multicast_addr));
        fprintf(stdout, "    %-*s %u\n", FIELD_WIDTH - 2, "Num Sources:", num_sources);

        const u_char *src_ptr = ptr + sizeof(IgmpV3GroupRecord);
        
        for (uint16_t j = 0; j < num_sources; j++) {
            if (src_ptr + sizeof(struct in_addr) > packet_end) {
                fprintf(stderr, "  [!] Warning: Truncated IGMPv3 Source Address.\n");
                break;
            }

            struct in_addr src_ip;
            memcpy(&src_ip, src_ptr + (j * sizeof(struct in_addr)), sizeof(struct in_addr));

            char src_label[32];
            snprintf(src_label, sizeof(src_label), "Source %u:", j + 1);
            fprintf(stdout, "      %-*s %s\n", FIELD_WIDTH - 4, src_label, inet_ntoa(src_ip));

            src_ptr += sizeof(struct in_addr);
        }

        uint32_t record_total_size = sizeof(IgmpV3GroupRecord) + 
                                     (num_sources * sizeof(struct in_addr)) + 
                                     (record->aux_data_len * 4);
        if (ptr + record_total_size > packet_end) {
            fprintf(stderr, "  [!] Warning: IGMPv3 Group Record data exceeds packet length. Stopping parse.\n");
            break;
        }

        ptr += record_total_size;
    }
}

void process_igmp_v3_query(const u_char *packet, uint16_t length) {
    if (!packet || length < IGMP_V3_QUERY_HEADER_LEN) {
        fprintf(stderr, "Error: invalid IGMP v3 Query packet.\n");
        return;
    }

    const IgmpV3QueryHeader *query = (const IgmpV3QueryHeader *)packet;
    uint16_t num_sources = ntohs(query->num_sources);

    fprintf(stdout, "  %-*s v3 Membership Query (0x11)\n", FIELD_WIDTH, "Type:");

    /* Decoding of Max Response Code as per RFC 3376 */
    uint16_t max_time;
    if (query->max_resp_code < 128) {
        max_time = query->max_resp_code;
    } else {
        uint8_t mant = query->max_resp_code & 0x0F;
        uint8_t exp  = (query->max_resp_code & 0x70) >> 4;
        max_time = (mant | 0x10) << (exp + 3);
    }
    fprintf(stdout, "  %-*s %u deciseconds (Code: 0x%02X)\n", FIELD_WIDTH, "Max Resp Time:", max_time, query->max_resp_code);

    fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Group Address:", inet_ntoa(query->group));
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Total Sources:", num_sources);

    /* Safety limit */
    const u_char *packet_end = packet + length;
    const u_char *ptr = packet + sizeof(IgmpV3QueryHeader);

    for (uint16_t i = 0; i < num_sources; i++) {
        if (ptr + sizeof(struct in_addr) > packet_end) {
            fprintf(stderr, "    [!] Warning: Truncated IGMPv3 Source Address. Stopping parse.\n");
            break;
        }

        struct in_addr src_ip;
        memcpy(&src_ip, ptr, sizeof(struct in_addr));

        char src_label[32];
        snprintf(src_label, sizeof(src_label), "Source %u:", i + 1);
        fprintf(stdout, "    %-*s %s\n", FIELD_WIDTH - 2, src_label, inet_ntoa(src_ip));

        ptr += sizeof(struct in_addr);
    }
}
