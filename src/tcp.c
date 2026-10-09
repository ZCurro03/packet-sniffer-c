#include <stdio.h>
#include <stdbool.h>
#include "../include/utils.h"
#include "../include/tcp.h"


/***********************************
 * Public functions implementation *
 ***********************************/

void process_tcp_segment(const u_char *segment, uint32_t length) {
    if (!segment || length < TCP_HEADER_MIN_LEN) {
        fprintf(stderr, "Error: invalid or truncated TCP segment.\n");
        return;
    }

    const TcpHeader *tcp_header = (const TcpHeader *)segment;

    uint8_t  data_offset    = (tcp_header->offset_res >> 4);
    uint32_t tcp_header_len = data_offset * 4;

    if (data_offset < TCP_MIN_DATA_OFFSET) {
        fprintf(stderr, "Error: malformed TCP segment (data offset %u is too small).\n", data_offset);
        return;
    }

    if (length < tcp_header_len) {
        fprintf(stderr, "Error: truncated TCP segment (requires %u bytes, got %u).\n", tcp_header_len, length);
        return;
    }

    uint16_t src_port = ntohs(tcp_header->src_port);
    uint16_t dst_port = ntohs(tcp_header->dest_port);
    uint32_t seq_num  = ntohl(tcp_header->seq_num);
    uint8_t flags     = tcp_header->flags;

    fprintf(stdout, "TCP Segment:\n");
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Source Port:", src_port);
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Destination Port:", dst_port);
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Sequence Number:", seq_num);

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Flags:");
    if (flags == 0) {
        fprintf(stdout, "None\n");
    } else {
        struct { uint8_t mask; const char* name; } flag_map[] = {
            {TCP_FLAG_SYN, "SYN"}, {TCP_FLAG_FIN, "FIN"}, {TCP_FLAG_RST, "RST"}, {TCP_FLAG_PSH, "PSH"},
            {TCP_FLAG_URG, "URG"}, {TCP_FLAG_ACK, "ACK"}, {TCP_FLAG_ECE, "ECE"}, {TCP_FLAG_CWR, "CWR"}
        };
        size_t num_flags = sizeof(flag_map) / sizeof(flag_map[0]);
        bool has_printed = false;

        for (size_t i = 0; i < num_flags; i++) {
            if (flags & flag_map[i].mask) {
                fprintf(stdout, "%s%s", has_printed ? "-" : "", flag_map[i].name);
                has_printed = true;
            }
        }
        fprintf(stdout, "\n");
    }

    /* Notify about the presence of TCP options */
    if (data_offset > TCP_MIN_DATA_OFFSET) {
        uint8_t options_len = tcp_header_len - TCP_HEADER_MIN_LEN;
        fprintf(stdout, "  %-*s %u bytes present\n", FIELD_WIDTH, "TCP Options:", options_len);
    }

    const u_char *app_payload = segment + tcp_header_len;
    uint32_t payload_len      = length - tcp_header_len;

    (void)app_payload;  /* Suppress unused variable warning */
    (void)payload_len;  /* Suppress unused variable warning */
}
