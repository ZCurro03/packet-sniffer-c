#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/arp.h"
#include "../include/ethernet.h"
#include "../include/ip.h"


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Prints the ARP operation code in a human-readable format.
 * @param opcode The ARP operation code.
 * @param is_probe Flag indicating if the packet is an ARP probe.
 * @param is_announcement Flag indicating if the packet is an ARP announcement.
 */
void print_opcode(uint16_t opcode, bool is_probe, bool is_announcement);


/***********************************
 * Public functions implementation *
 ***********************************/

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

    const u_char *sender_hw   = packet + sizeof(ArpBaseHeader);
    const u_char *sender_prot = sender_hw + hlen;
    const u_char *target_hw   = sender_prot + plen;
    const u_char *target_prot = target_hw + hlen;

    bool is_eth  = (hw_type == ARP_HW_TYPE_ETHERNET && hlen == ETHERNET_ADDR_LEN);
    bool is_ipv4 = (proto_type == ARP_PROTO_TYPE_IPV4 && plen == IPV4_ADDR_LEN);
    bool is_probe = false;
    bool is_announcement = false;

    struct in_addr sip, tip;
    if (is_ipv4) {
        memcpy(&sip, sender_prot, IPV4_ADDR_LEN);
        memcpy(&tip, target_prot, IPV4_ADDR_LEN);
        
        is_probe = (sip.s_addr == 0);
        is_announcement = (sip.s_addr == tip.s_addr) && (sip.s_addr != 0);
    }

    fprintf(stdout, "ARP packet:\n");

    print_opcode(opcode, is_probe, is_announcement);

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Hardware Type:");
    switch (hw_type) {
        case ARP_HW_TYPE_ETHERNET:
            fprintf(stdout, "Ethernet");
            break;
        default:
            fprintf(stdout, "Other");
            break;
    }
    fprintf(stdout, " (%u)\n", hw_type);

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Protocol Type:");
    switch (proto_type) {
        case ARP_PROTO_TYPE_IPV4:
            fprintf(stdout, "IPv4");
            break;
        default:
            fprintf(stdout, "Other");
            break;
    }
    fprintf(stdout, " (0x%04X)\n", proto_type);

    /* Formatted display for Ethernet and IPv4 */
    if (is_eth) {
        fprintf(stdout, "  %-*s %02X:%02X:%02X:%02X:%02X:%02X\n",
                FIELD_WIDTH, "Sender MAC:",
                sender_hw[0], sender_hw[1], sender_hw[2],
                sender_hw[3], sender_hw[4], sender_hw[5]);

        fprintf(stdout, "  %-*s %02X:%02X:%02X:%02X:%02X:%02X\n",
                FIELD_WIDTH, "Target MAC:",
                target_hw[0], target_hw[1], target_hw[2],
                target_hw[3], target_hw[4], target_hw[5]);
    } else {
        fprintf(stdout, "Hardware addresses parsing unsupported (Type: %u, HLEN: %u).\n", hw_type, hlen);
    }

    if (is_ipv4) {
        fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Sender IP:", inet_ntoa(sip));
        fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Target IP:", inet_ntoa(tip));
    } else {
        fprintf(stdout, "Network protocol addresses parsing unsupported (Type: 0x%04X, PLEN: %u).\n", 
                proto_type, plen);
    }
}


/************************************
 * Private functions implementation *
 ************************************/

void print_opcode(uint16_t opcode, bool is_probe, bool is_announcement) {
    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Operation:");
    switch (opcode) {
        case ARP_OPCODE_REQUEST:
            fprintf(stdout, "Request");
            if (is_probe) {
                fprintf(stdout, " - ARP Probe");
            } else if (is_announcement) {
                fprintf(stdout, " - ARP Announcement");
            }
            break;
        case ARP_OPCODE_REPLY:
            fprintf(stdout, "Reply");
            if (is_announcement) {
                fprintf(stdout, " - ARP Announcement");
            }
            break;
        case RARP_OPCODE_REQUEST:
            fprintf(stdout, "Reverse ARP Request");
            break;
        case RARP_OPCODE_REPLY:
            fprintf(stdout, "Reverse ARP Reply");
            break;
        case INARP_OPCODE_REQUEST:
            fprintf(stdout, "Inverse ARP Request");
            break;
        case INARP_OPCODE_REPLY:
            fprintf(stdout, "Inverse ARP Reply");
            break;
        default:
            fprintf(stdout, "Other");
            break;
    }
    fprintf(stdout, " (%u)\n", opcode);
}
