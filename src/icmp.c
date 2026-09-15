#include <stdio.h>
#include "../include/utils.h"
#include "../include/ip.h"
#include "../include/icmp.h"


/***********************************
 * Public functions implementation *
 ***********************************/

void process_icmp_message(const u_char *message) {
    if (!message) {
        fprintf(stderr, "Error: invalid ICMP message.\n");
        return;
    }

    const IcmpHeader *icmp = (const IcmpHeader *)message;

    fprintf(stdout, "ICMP Message:\n");

    fprintf(stdout, "  %-*s ", FIELD_WIDTH, "Type:");
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

    fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Code:", icmp->code);
    
    /* Display additional information for Echo messages */
    if (icmp->type == ICMP_TYPE_ECHO_REQUEST || icmp->type == ICMP_TYPE_ECHO_REPLY) {
        uint16_t identifier = ntohs(icmp->identifier);
        uint16_t sequence   = ntohs(icmp->sequence);
        
        fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Identifier:", identifier);
        fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Sequence Num:", sequence);
    }

    if (icmp->type == ICMP_TYPE_DEST_UNREACH || icmp->type == ICMP_TYPE_TIME_EXCEEDED) {
        const IPv4Header *inner_ip = (const IPv4Header *)(message + sizeof(IcmpHeader));

        fprintf(stdout, "Original Failed IPv4 Packet:\n");
        fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Original Src IP:", inet_ntoa(inner_ip->src_ip));
        fprintf(stdout, "  %-*s %s\n", FIELD_WIDTH, "Original Dst IP:", inet_ntoa(inner_ip->dest_ip));
        fprintf(stdout, "  %-*s %u\n", FIELD_WIDTH, "Original Protocol:", inner_ip->protocol);
    }
}
