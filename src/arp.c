#include <stdio.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/arp.h"
#include "../include/ethernet.h"
#include "../include/ip.h"



void process_arp_packet(const u_char *packet) {
    if (!packet) {
        fprintf(stderr, "Error: invalid ARP packet.\n");
        return;
    }

    const ArpBaseHeader *arp = (const ArpBaseHeader *)packet;

    uint16_t hw_type = ntohs(arp->hw_type);
    uint16_t proto_type = ntohs(arp->proto_type);
    uint16_t opcode = ntohs(arp->opcode);
    uint8_t hlen = arp->hlen;
    uint8_t plen = arp->plen;

    fprintf(stdout, "ARP packet:\n");

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Operation:");
    switch (opcode) {
        case ARP_OPCODE_REQUEST:
            fprintf(stdout, "Request (%d)\n", ARP_OPCODE_REQUEST);
            break;
        case ARP_OPCODE_REPLY:
            fprintf(stdout, "Reply (%d)\n", ARP_OPCODE_REPLY);
            break;
        default:
            fprintf(stdout, "Other (%u)\n", opcode);
            break;
    }

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Hardware Type:");
    switch (hw_type) {
        case ARP_HW_TYPE_ETHERNET:
            fprintf(stdout, "Ethernet (%d)\n", ARP_HW_TYPE_ETHERNET);
            break;
        default:
            fprintf(stdout, "Other (%u)\n", hw_type);
            break;
    }

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Protocol Type:");
    switch (proto_type) {
        case ARP_PROTO_TYPE_IPV4:
            fprintf(stdout, "IPv4 (0x%04X)\n", ARP_PROTO_TYPE_IPV4);
            break;
        default:
            fprintf(stdout, "Other (0x%04X)\n", proto_type);
            break;
    }

    const u_char *sender_hw   = packet + sizeof(ArpBaseHeader);
    const u_char *sender_prot = sender_hw + hlen;
    const u_char *target_hw   = sender_prot + plen;
    const u_char *target_prot = target_hw + hlen;

    /* Formatted display for Ethernet + IPv4 */
    if (hw_type == ARP_HW_TYPE_ETHERNET && proto_type == ARP_PROTO_TYPE_IPV4
            && hlen == ETHERNET_ADDR_LEN && plen == IPV4_ADDR_LEN) {
        fprintf(stdout, "  %-*s %02X:%02X:%02X:%02X:%02X:%02X\n",
                FIELD_WIDTH, "Sender MAC:",
                sender_hw[0], sender_hw[1], sender_hw[2],
                sender_hw[3], sender_hw[4], sender_hw[5]);

        if (opcode == ARP_OPCODE_REPLY) {
            fprintf(stdout, "  %-*s %02X:%02X:%02X:%02X:%02X:%02X\n",
                    FIELD_WIDTH, "Target MAC:",
                    target_hw[0], target_hw[1], target_hw[2],
                    target_hw[3], target_hw[4], target_hw[5]);
        }

        struct in_addr sip, tip;
        memcpy(&sip, sender_prot, IPV4_ADDR_LEN);
        memcpy(&tip, target_prot, IPV4_ADDR_LEN);

        fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Sender IP:", inet_ntoa(sip));
        fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Target IP:", inet_ntoa(tip));
    } else {
        fprintf(stdout, "Unsupported link or network protocol (HW Type: %u, Proto: 0x%04X). Skipping detailed parsing.\n", 
                hw_type, proto_type);
    }
}
