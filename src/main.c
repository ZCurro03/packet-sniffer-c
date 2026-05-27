#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    pcap_if_t *alldevs = NULL;
	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't find available devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    pcap_if_t *dev = alldevs;
    size_t dev_count = 0;
    while (dev != NULL) {
        fprintf(stdout, "Device %ld: %s. %s.\n", dev_count + 1, dev->name, dev->description);

        dev_count++;
        dev = dev->next;
    }

    pcap_freealldevs(alldevs);

    return EXIT_SUCCESS;
}