#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../include/packet_handler.h"
#include "../include/ethernet.h"

#define TIMESTAMP_STR_SZ 16


void timestamp_to_str(struct timeval ts, char *buff, size_t sz);


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) {
        fprintf(stderr, "Error: invalid packet or header received.\n");
        return;
    }
    (void)args; /* Unused parameter */
    
    char timestamp[TIMESTAMP_STR_SZ] = {0};

    timestamp_to_str(header->ts, timestamp, sizeof(timestamp));

    fprintf(stdout, "[%s] Packet received (length: %d).\n", timestamp, header->len);

    process_ethernet_frame(packet);

    fprintf(stdout, "--------------------------------------------------\n");
}

void timestamp_to_str(struct timeval ts, char *buff, size_t sz) {
    if (!buff || sz < TIMESTAMP_STR_SZ) {
        memset(buff, 0, sz);
        return;
    }
    
    /* HH:MM:SS --> Hour, minute and second in local time */
    time_t local_tv_sec = ts.tv_sec;
    struct tm *local_time = localtime(&local_tv_sec);
    strftime(buff, sz, "%H:%M:%S", local_time);

    /* .mmmmmm --> microseconds (6 digits) */
    char microseconds[8] = {0};
    snprintf(microseconds, 8, ".%06d", (int)ts.tv_usec);
    strncat(buff, microseconds, 7);

    /* Final string: "HH:MM:SS.mmmmmm" */
    buff[TIMESTAMP_STR_SZ - 1] = '\0';
}
