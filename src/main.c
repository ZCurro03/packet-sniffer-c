#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <pcap/pcap.h>
#include "../include/packet_handler.h"
#include "../include/signal_handler.h"
#include "../include/device_manager.h"
#include "../include/ui.h"


/*****************************
 * Macros & Global Variables *
 *****************************/

#define IP_PACKET_SZ 65535      /* Max size of an IP packet */

pcap_t *sniff_handle = NULL;    /* The pcap handle for the active capture session */


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Handles the SIGINT (Ctrl+C) signal to interrupt the capture loop.
 * @param signum Number of the received signal.
 */
void handle_sigint(int signum);

/********
 * Main *
 ********/

int main() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (!set_signal_handler(SIGINT, handle_sigint)) {
        return EXIT_FAILURE;
    }

    DeviceManager *manager = device_manager_init();
    if (manager == NULL) {
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");

    ui_display_available_devices(device_manager_get_all_devices(manager));

    fprintf(stdout, "\n");

    size_t selected_dev_idx = ui_prompt_for_device_selection(device_manager_get_device_count(manager));
    if (selected_dev_idx == 0) {
        fprintf(stdout, "No valid device selected. Quitting...\n");
        device_manager_free(manager);
        return EXIT_FAILURE;
    }

    /* User input is expected to be between 1 and dev_count, so we subtract 1 to get the zero-based index */
    device_manager_set_selected_device_index(manager, selected_dev_idx - 1);

    pcap_if_t *dev = device_manager_get_selected_device(manager);
    fprintf(stdout, "\nSniffing device: %s.\n", dev != NULL ? dev->name : "none");

    sniff_handle = pcap_open_live(dev->name, IP_PACKET_SZ, 1, 1000, errbuf);
    if (sniff_handle == NULL) {
        fprintf(stderr, "Couldn't open device '%s': %s\n", dev->name, errbuf);
        device_manager_free(manager);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Sniffing session created successfully.\n");

    /* Use -1 to sniff until an error occurs */
    pcap_loop(sniff_handle, -1, process_packet, NULL);

    pcap_close(sniff_handle);
    device_manager_free(manager);

    fprintf(stdout, "Sniffing session closed.\n");

    return EXIT_SUCCESS;
}

/************************************
 * Private functions implementation *
 ************************************/

void handle_sigint(int signum) {
    if (signum == SIGINT && sniff_handle != NULL) {
        pcap_breakloop(sniff_handle);
    }
}
