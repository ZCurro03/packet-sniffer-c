#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap/pcap.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* PACKET_HANDLER_H */
