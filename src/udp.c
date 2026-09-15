#include <stdio.h>
#include <stdbool.h>
#include "../include/utils.h"
#include "../include/udp.h"


/***********************************
 * Public functions implementation *
 ***********************************/

void process_udp_datagram(const u_char *datagram) {
    if (!datagram) {
        fprintf(stderr, "Error: invalid UDP datagram.\n");
        return;
    }

    const UdpHeader *udp_header = (const UdpHeader *)datagram;

    uint16_t src_port = ntohs(udp_header->src_port);
    uint16_t dst_port = ntohs(udp_header->dest_port);
    uint16_t len      = ntohs(udp_header->len);

    fprintf(stdout, "UDP datagram:\n");
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Source Port:", src_port);
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Destination Port:", dst_port);
    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Total Length:", len);

    const u_char *app_payload = datagram + sizeof(UdpHeader);
    uint16_t payload_len      = len - sizeof(UdpHeader);

    (void)app_payload;  /* Suppress unused variable warning */
    (void)payload_len;  /* Suppress unused variable warning */
}
