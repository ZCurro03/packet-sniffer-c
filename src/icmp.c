#include <stdio.h>
#include "../include/utils.h"
#include "../include/ui.h"
#include "../include/ipv4.h"
#include "../include/icmp.h"


/***********************************
 * Public functions implementation *
 ***********************************/

void process_icmp_message(const u_char *message, uint32_t length) {
    if (!message || length < ICMP_HEADER_LEN) {
        fprintf(stderr, "Error: invalid or truncated ICMP message.\n");
        return;
    }

    const IcmpHeader *icmp = (const IcmpHeader *)message;

    fprintf(stdout, "%s ICMP\n", TREE_PROT);

    fprintf(stdout, "%s %-*s ", TREE_ITEM, FIELD_WIDTH, "Type:");
    switch (icmp->type) {
        case ICMP_TYPE_ECHO_REPLY:
            fprintf(stdout, "Echo Reply");
            break;
        case ICMP_TYPE_ECHO_REQUEST:
            fprintf(stdout, "Echo Request");
            break;
        case ICMP_TYPE_REDIRECT:
            fprintf(stdout, "Redirect");
            break;
        case ICMP_TYPE_DEST_UNREACH:
            fprintf(stdout, "Destination Unreachable");
            break;
        case ICMP_TYPE_TIME_EXCEEDED:
            fprintf(stdout, "Time Exceeded");
            break;
        default:
            fprintf(stdout, "Other");
            break;
    }
    fprintf(stdout, " (%u)\n", icmp->type);

    bool is_echo = (icmp->type == ICMP_TYPE_ECHO_REQUEST || icmp->type == ICMP_TYPE_ECHO_REPLY);
    bool is_error = (icmp->type == ICMP_TYPE_DEST_UNREACH || icmp->type == ICMP_TYPE_TIME_EXCEEDED);

    fprintf(stdout, "%s %-*s %u\n", (is_echo || is_error) ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Code:", icmp->code);

    if (is_echo) {
        uint16_t identifier = ntohs(icmp->identifier);
        uint16_t sequence   = ntohs(icmp->sequence);

        fprintf(stdout, "%s %-*s %u\n", TREE_ITEM, FIELD_WIDTH, "Identifier:", identifier);
        fprintf(stdout, "%s %-*s %u\n", TREE_LAST, FIELD_WIDTH, "Sequence Num:", sequence);
    } else if (is_error) {
        uint32_t required_len = sizeof(IcmpHeader) + sizeof(IPv4Header);
        if (length < required_len) {
            fprintf(stderr, "Error: truncated ICMP error message (missing inner IPv4 header).\n");
            return;
        }

        const IPv4Header *inner_ip = (const IPv4Header *)(message + sizeof(IcmpHeader));

        fprintf(stdout, "%s %-*s %s\n", TREE_ITEM, FIELD_WIDTH, "Original Src IP:", inet_ntoa(inner_ip->src_ip));
        fprintf(stdout, "%s %-*s %s\n", TREE_ITEM, FIELD_WIDTH, "Original Dst IP:", inet_ntoa(inner_ip->dest_ip));
        fprintf(stdout, "%s %-*s %u\n", TREE_LAST, FIELD_WIDTH, "Original Protocol:", inner_ip->protocol);
    }
}
