#include <stdio.h>
#include <stdbool.h>
#include "../include/utils.h"
#include "../include/udp.h"


/***********************************
 * Public functions implementation *
 ***********************************/

void process_udp_datagram(const u_char *datagram, uint32_t length) {
    if (!datagram || length < UDP_HEADER_LEN) {
        fprintf(stderr, "Error: invalid or truncated UDP datagram.\n");
        return;
    }

    const UdpHeader *udp_header = (const UdpHeader *)datagram;

    uint16_t src_port = ntohs(udp_header->src_port);
    uint16_t dst_port = ntohs(udp_header->dest_port);
    uint16_t total_length = ntohs(udp_header->len);

    if (total_length < UDP_HEADER_LEN) {
        fprintf(stderr, "Error: malformed UDP datagram (total length is smaller than header length).\n");
        return;
    }

    fprintf(stdout, "UDP datagram:\n");
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Source Port:", src_port);
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Destination Port:", dst_port);
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Total Length:", total_length);

    uint32_t expected_payload_len = total_length - UDP_HEADER_LEN;
    uint32_t captured_payload_len = length - UDP_HEADER_LEN;

    /* If the packet claims to be larger than what we actually captured, we limit ourselves strictly to what was captured */
    uint32_t safe_payload_len = expected_payload_len;
    if (expected_payload_len > captured_payload_len) {
        fprintf(stdout, "  [!] Warning: UDP payload may have been truncated during capture (%u of %u bytes available)\n",
                captured_payload_len, expected_payload_len);
        safe_payload_len = captured_payload_len;
    }

    const u_char *app_payload = datagram + UDP_HEADER_LEN;

    (void)app_payload;       /* Suppress unused variable warning */
    (void)safe_payload_len;  /* Suppress unused variable warning */
}
