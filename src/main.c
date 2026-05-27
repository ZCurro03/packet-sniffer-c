#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>

#define IP_PACKET_SZ 65535

pcap_t *sniff_handle = NULL;

void handle_sigint(int signum) {
    if (signum == SIGINT && sniff_handle != NULL) {
        pcap_breakloop(sniff_handle);
    }
}

bool set_signal_handler(int signum, void (*handler)(int)) {
    struct sigaction action = {0};

    /* Block all signals during the handler's execution to avoid interruptions */
    sigfillset(&(action.sa_mask));
    action.sa_handler = handler;
    action.sa_flags = 0;

    if (sigaction(signum, &action, NULL) == -1) {
        perror("sigaction");
        return false;
    }

    return true;
}

void list_all_available_devices(pcap_if_t *alldevs, size_t *count) {
    if (count == NULL) {
        fprintf(stderr, "Error in list_all_available_devices: NULL pointer 'count'.\n");
        return;
    }
    
    if (alldevs == NULL) {
        fprintf(stdout, "No available devices found.\n");
        *count = 0;
        return;
    }

    pcap_if_t *dev = NULL;
    size_t dev_count = 0;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        fprintf(stdout, "Device %ld: %s", dev_count + 1, dev->name);
        if (dev->description != NULL) fprintf(stdout, " (%s)", dev->description);
        fprintf(stdout, ".\n");

        dev_count++;
    }

    *count = dev_count;
}

pcap_if_t* get_sniffing_device(pcap_if_t *alldevs, size_t dev_count) {
    if (alldevs == NULL || dev_count == 0) {
        fprintf(stdout, "No available devices to sniff on.\n");
        return NULL;
    }

    long selected_dev_idx = 0;
    bool valid_idx = false;
    char idx_buff[16] = {0};
    do {
        fprintf(stdout, "Enter the index of the device to sniff on (1-%ld) > ", dev_count);
        
        memset(idx_buff, 0, sizeof(idx_buff));
        if (fgets(idx_buff, sizeof(idx_buff), stdin) != NULL) {
            char *newline = strchr(idx_buff, '\n');
            if (newline == NULL) { /* Read line was longer than the buffer, so stdin must be cleaned */
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
            } else {
                *newline = '\0';
            }
        } else {
            perror("Input error or EOF detected");
            return NULL;
        }

        char *endptr = NULL;
        selected_dev_idx = strtol(idx_buff, &endptr, 10);

        valid_idx = endptr != idx_buff && *endptr == '\0' &&
            selected_dev_idx >= 1 && (size_t)selected_dev_idx <= dev_count;

        if (!valid_idx) {
            fprintf(stdout, "Invalid index. Please, try again.\n");
        }
    } while (!valid_idx);

    pcap_if_t *dev = alldevs;
    while (selected_dev_idx > 1 && dev != NULL) {
        dev = dev->next;
        selected_dev_idx--;
    }

    return dev;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static size_t count = 1;
    fprintf(stdout, "Packet %ld received.\n", count);
    count++;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (!set_signal_handler(SIGINT, handle_sigint)) {
        return EXIT_FAILURE;
    }

    pcap_if_t *alldevs = NULL;
	if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't find available devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    size_t dev_count = 0;
    fprintf(stdout, "Listing all available devices...\n");
    list_all_available_devices(alldevs, &dev_count);

    fprintf(stdout, "-------------\n\n");
    pcap_if_t *dev = get_sniffing_device(alldevs, dev_count);
    if (dev == NULL) {
        fprintf(stdout, "No sniffing device set. Quitting...\n");
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Sniffing device: %s.\n", dev != NULL ? dev->name : "none");

    sniff_handle = pcap_open_live(dev->name, IP_PACKET_SZ, 1, 1000, errbuf);
    if (sniff_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Sniffing session created successfully.\n");
    fprintf(stdout, "-------------\n\n");

    /* Use -1 to sniff until an error occurs */
    pcap_loop(sniff_handle, -1, got_packet, NULL);

    pcap_close(sniff_handle);
    pcap_freealldevs(alldevs);

    fprintf(stdout, "Sniffing session closed.\n");

    return EXIT_SUCCESS;
}