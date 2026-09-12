#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap/pcap.h>


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Process a captured packet.
 * @param args User-defined arguments (unused).
 * @param header Packet header.
 * @param packet Packet data.
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* PACKET_HANDLER_H */
