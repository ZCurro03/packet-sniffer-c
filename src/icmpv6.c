#include <stdio.h>
#include <stdbool.h>
#include "../include/ui.h"
#include "../include/icmpv6.h"


/***********************************
 * Private functions declaration *
 ***********************************/

/**
 * Retrieves the name of the ICMPv6 message type based on its type value.
 * @param type The ICMPv6 message type value.
 * @return A string representing the name of the ICMPv6 message type.
 */
static const char* get_icmpv6_type_name(uint8_t type);

/**
 * Processes an ICMPv6 Packet Too Big message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_ptb_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 Parameter Problem message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_pp_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 Echo Request or Echo Reply message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_echo_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 Router Advertisement message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_router_adv_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 Neighbor Solicitation message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_neighbor_sol_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 Neighbor Advertisement message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_neighbor_adv_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 Redirect message.
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_redirect_message(const u_char *message, uint32_t length);

/**
 * Processes an ICMPv6 message with just an extra reserved or unused field (plus optional additional data).
 * @param message The raw ICMPv6 message to process.
 * @param length The length of the ICMPv6 message.
 * @return true if the message was valid and processed successfully, false otherwise.
 */
static bool process_icmpv6_reserved_message(const u_char *message, uint32_t length);


/***********************************
 * Public functions implementation *
 ***********************************/

void process_icmpv6_message(const u_char *message, uint32_t length) {
    if (!message || length < ICMPV6_HEADER_LEN) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 message.\n");
        return;
    }

    const Icmpv6Header *icmpv6_header = (const Icmpv6Header *)message;
    uint32_t length_remaining = length - ICMPV6_HEADER_LEN;

    fprintf(stdout, "%s ICMPv6\n", TREE_PROT);

    const char *type_name = get_icmpv6_type_name(icmpv6_header->type);

    fprintf(stdout, "%s %-*s %s (%u)\n", TREE_ITEM, FIELD_WIDTH, "Type:", type_name, icmpv6_header->type);
    fprintf(stdout, "%s %-*s %u\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Code:", icmpv6_header->code);

    switch (icmpv6_header->type) {
        case ICMPV6_TYPE_PACKET_TOO_BIG:
            if (process_icmpv6_ptb_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6ErrorMtu);
            }
            break;
        case ICMPV6_TYPE_PARAM_PROBLEM:
            if (process_icmpv6_pp_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6ErrorPointer);
            }
            break;
        case ICMPV6_TYPE_ECHO_REQUEST:
        case ICMPV6_TYPE_ECHO_REPLY:
            if (process_icmpv6_echo_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6EchoFields);
            }
            break;
        case ICMPV6_TYPE_ROUTER_ADV:
            if (process_icmpv6_router_adv_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6NdRouterAdv);
            }
            break;
        case ICMPV6_TYPE_NEIGHBOR_SOL:
            if (process_icmpv6_neighbor_sol_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6NdNeighborSol);
            }
            break;
        case ICMPV6_TYPE_NEIGHBOR_ADV:
            if (process_icmpv6_neighbor_adv_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6NdNeighborAdv);
            }
            break;
        case ICMPV6_TYPE_REDIRECT:
            if (process_icmpv6_redirect_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6NdRedirect);
            }
            break;
        case ICMPV6_TYPE_DEST_UNREACH:
        case ICMPV6_TYPE_TIME_EXCEEDED:
        case ICMPV6_TYPE_ROUTER_SOL:
        case ICMPV6_TYPE_INV_NEIGHBOR_SOL:
        case ICMPV6_TYPE_INV_NEIGHBOR_ADV:
            if (process_icmpv6_reserved_message(message + ICMPV6_HEADER_LEN, length - ICMPV6_HEADER_LEN)) {
                length_remaining -= sizeof(Icmpv6Reserved4);
            }
            break;
        default:
            break;  /* For other types, no specific processing implemented */
    }

    if (length_remaining > 0) {
        fprintf(stdout, "%s %-*s %u bytes\n", TREE_LAST, FIELD_WIDTH, "Additional Data:", length_remaining);
    }
}


/************************************
 * Private functions implementation *
 ************************************/

static const char* get_icmpv6_type_name(uint8_t type) {
    switch (type) {
        case ICMPV6_TYPE_DEST_UNREACH:
            return "Destination Unreachable";
        case ICMPV6_TYPE_PACKET_TOO_BIG:
            return "Packet Too Big";
        case ICMPV6_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMPV6_TYPE_PARAM_PROBLEM:
            return "Parameter Problem";
        case ICMPV6_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case ICMPV6_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case ICMPV6_TYPE_ROUTER_SOL:
            return "Router Solicitation";
        case ICMPV6_TYPE_ROUTER_ADV:
            return "Router Advertisement";
        case ICMPV6_TYPE_NEIGHBOR_SOL:
            return "Neighbor Solicitation";
        case ICMPV6_TYPE_NEIGHBOR_ADV:
            return "Neighbor Advertisement";
        case ICMPV6_TYPE_REDIRECT:
            return "Redirect";
        case ICMPV6_TYPE_INV_NEIGHBOR_SOL:
            return "Inverse Neighbor Solicitation";
        case ICMPV6_TYPE_INV_NEIGHBOR_ADV:
            return "Inverse Neighbor Advertisement";
        default:
            return "Other";
    }
}

static bool process_icmpv6_ptb_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6ErrorMtu)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Packet Too Big message.\n");
        return false;
    }

    const Icmpv6ErrorMtu *ptb_fields = (const Icmpv6ErrorMtu *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6ErrorMtu);

    fprintf(stdout, "%s %-*s %u\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "MTU:", ntohl(ptb_fields->mtu));

    return true;
}

static bool process_icmpv6_pp_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6ErrorPointer)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Parameter Problem message.\n");
        return false;
    }

    const Icmpv6ErrorPointer *pp_fields = (const Icmpv6ErrorPointer *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6ErrorPointer);

    fprintf(stdout, "%s %-*s %u\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Pointer:", ntohl(pp_fields->pointer));

    return true;
}

static bool process_icmpv6_echo_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6EchoFields)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Echo message.\n");
        return false;
    }

    const Icmpv6EchoFields *echo_fields = (const Icmpv6EchoFields *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6EchoFields);

    fprintf(stdout, "%s %-*s %u\n", TREE_ITEM, FIELD_WIDTH, "Identifier:", echo_fields->identifier);
    fprintf(stdout, "%s %-*s %u\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Sequence:", echo_fields->sequence);

    return true;
}

static bool process_icmpv6_router_adv_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6NdRouterAdv)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Router Advertisement message.\n");
        return false;
    }

    const Icmpv6NdRouterAdv *ra_fields = (const Icmpv6NdRouterAdv *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6NdRouterAdv);

    fprintf(stdout, "%s %-*s %u\n", TREE_ITEM, FIELD_WIDTH, "Current Hop Limit:", ra_fields->cur_hop_limit);
    fprintf(stdout, "%s %-*s 0x%02X\n", TREE_ITEM, FIELD_WIDTH, "Flags:", ra_fields->flags);
    fprintf(stdout, "%s %-*s %u\n", TREE_ITEM, FIELD_WIDTH, "Router Lifetime:", ntohs(ra_fields->router_lifetime));
    fprintf(stdout, "%s %-*s %u ms\n", TREE_ITEM, FIELD_WIDTH, "Reachable Time:", ntohl(ra_fields->reachable_time));
    fprintf(stdout, "%s %-*s %u ms\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Retrans Timer:", ntohl(ra_fields->retrans_timer));

    return true;
}

static bool process_icmpv6_neighbor_sol_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6NdNeighborSol)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Neighbor Solicitation message.\n");
        return false;
    }

    const Icmpv6NdNeighborSol *ns_fields = (const Icmpv6NdNeighborSol *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6NdNeighborSol);

    char ip_str[INET6_ADDRSTRLEN] = "";
    inet_ntop(AF_INET6, ns_fields->target_addr, ip_str, INET6_ADDRSTRLEN);

    fprintf(stdout, "%s %-*s 0x%08X\n", TREE_ITEM, FIELD_WIDTH, "Reserved:", ntohl(ns_fields->reserved));
    fprintf(stdout, "%s %-*s %s\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Target Address:", ip_str);

    return true;
}

static bool process_icmpv6_neighbor_adv_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6NdNeighborAdv)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Neighbor Advertisement message.\n");
        return false;
    }

    const Icmpv6NdNeighborAdv *na_fields = (const Icmpv6NdNeighborAdv *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6NdNeighborAdv);

    char ip_str[INET6_ADDRSTRLEN] = "";
    inet_ntop(AF_INET6, na_fields->target_addr, ip_str, INET6_ADDRSTRLEN);

    fprintf(stdout, "%s %-*s 0x%08X\n", TREE_ITEM, FIELD_WIDTH, "Flags:", ntohl(na_fields->flags));
    fprintf(stdout, "%s %-*s %s\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Target Address:", ip_str);

    return true;
}

static bool process_icmpv6_redirect_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6NdRedirect)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 Redirect message.\n");
        return false;
    }

    const Icmpv6NdRedirect *redirect_fields = (const Icmpv6NdRedirect *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6NdRedirect);

    char target_ip_str[INET6_ADDRSTRLEN] = "";
    char dest_ip_str[INET6_ADDRSTRLEN] = "";
    inet_ntop(AF_INET6, redirect_fields->target_addr, target_ip_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, redirect_fields->dest_addr, dest_ip_str, INET6_ADDRSTRLEN);

    fprintf(stdout, "%s %-*s 0x%08X\n", TREE_ITEM, FIELD_WIDTH, "Reserved:", ntohl(redirect_fields->reserved));
    fprintf(stdout, "%s %-*s %s\n", TREE_ITEM, FIELD_WIDTH, "Target Address:", target_ip_str);
    fprintf(stdout, "%s %-*s %s\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Dest Address:", dest_ip_str);

    return true;
}

static bool process_icmpv6_reserved_message(const u_char *message, uint32_t length) {
    if (!message || length < sizeof(Icmpv6Reserved4)) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 message (missing reserved field).\n");
        return false;
    }

    const Icmpv6Reserved4 *rs_fields = (const Icmpv6Reserved4 *)message;
    uint32_t length_remaining = length - sizeof(Icmpv6Reserved4);

    fprintf(stdout, "%s %-*s 0x%08X\n", length_remaining > 0 ? TREE_ITEM : TREE_LAST, FIELD_WIDTH, "Reserved/Unused:", ntohl(rs_fields->reserved));

    return true;
}
