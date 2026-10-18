#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include "../include/packet_handler.h"
#include "../include/signal_handler.h"
#include "../include/device_manager.h"
#include "../include/ui.h"


/*****************************
 * Macros & Global Variables *
 *****************************/

#define MAX_CAPLEN 65535        /* Maximum capture length for the pcap library */
#define PROMISC 1               /* Enable promiscuous mode */

pcap_t *sniff_handle = NULL;    /* The pcap handle for the active capture session */


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Handles the SIGINT (Ctrl+C) signal to interrupt the capture loop.
 * @param signum Number of the received signal.
 */
void handle_sigint(int signum);

/**
 * Parses command-line arguments to determine the target device or pcap file.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param target_dev Pointer to store the selected device name.
 * @param pcap_file Pointer to store the selected pcap file name.
 * @return true if arguments were parsed successfully, false otherwise.
 */
bool parse_arguments(int argc, char *argv[], char **target_dev, char **pcap_file);

/**
 * Prints the usage information for the program.
 * @param prog_name The name of the program.
 */
void print_usage(const char *prog_name);

/**
 * Runs a live packet capture session, either on the specified device or in interactive mode.
 * @param target_dev The name of the device to capture on, or NULL for interactive mode.
 * @return true if the capture was successful, false otherwise.
 */
bool run_live_capture(const char *target_dev);


/********
 * Main *
 ********/

int main(int argc, char *argv[]) {
    if (!set_signal_handler(SIGINT, handle_sigint)) {
        exit(EXIT_FAILURE);
    }

    ui_configure_terminal();
    atexit(ui_restore_terminal);  /* Ensure terminal settings are restored on exit */

    char *target_dev = NULL, *pcap_file = NULL;
    if (!parse_arguments(argc, argv, &target_dev, &pcap_file)) {
        exit(EXIT_FAILURE);
    }

    ui_print_header();

    if (pcap_file) {
        fprintf(stdout, "Mode: Offline analysis from file '%s'.\n\n", pcap_file);
        fprintf(stdout, "\nTo be implemented.\n");
    } else {
        if (!run_live_capture(target_dev)) {
            exit(EXIT_FAILURE);
        }
    }

    exit(EXIT_SUCCESS);
}


/************************************
 * Private functions implementation *
 ************************************/

void handle_sigint(int signum) {
    if (signum == SIGINT && sniff_handle != NULL) {
        pcap_breakloop(sniff_handle);
    }
}

bool parse_arguments(int argc, char *argv[], char **target_dev, char **pcap_file) {
    if (!target_dev || !pcap_file) {
        fprintf(stderr, "Error: Invalid argument pointers provided.\n");
        return false;
    }

    opterr = 0;  /* Disable default error messages */

    int opt;
    while ((opt = getopt(argc, argv, ":i:r:h")) != -1) {
        switch (opt) {
            case 'i':
                *target_dev = optarg;
                break;
            case 'r':
                *pcap_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return false;
            case ':':
                fprintf(stderr, "Error: Option -%c requires an argument.\n", optopt);
                print_usage(argv[0]);
                return false;
            case '?':
                fprintf(stderr, "Error: Unknown option '-%c'.\n", optopt);
                print_usage(argv[0]);
                return false;
            default:
                print_usage(argv[0]);
                return false;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected positional arguments.\n");
        print_usage(argv[0]);
        return false;
    }

    if (*target_dev != NULL && *pcap_file != NULL) {
        fprintf(stderr, "Error: Options -i and -r are mutually exclusive.\n");
        print_usage(argv[0]);
        return false;
    }

    return true;
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [-i interface] [-r pcap_file]\n", prog_name);
    fprintf(stderr, "  -i <interface>   Listen on the specified interface\n");
    fprintf(stderr, "  -r <pcap_file>   Read packets from a pcap file\n");
    fprintf(stderr, "  -h               Show this help message\n");
}

bool run_live_capture(const char *target_dev) {
    const char *device_name = NULL;
    DeviceManager *manager = NULL;

    if (target_dev) {  /* Live capture on a specific interface */
        device_name = target_dev;
    } else {  /* Interactive live capture */
        manager = device_manager_init();
        if (manager == NULL) {
            return false;
        }

        ui_display_available_devices(device_manager_get_all_devices(manager));
        fprintf(stdout, "\n");

        size_t selected_dev_idx = ui_prompt_for_device_selection(device_manager_get_device_count(manager));
        if (selected_dev_idx == 0) {
            fprintf(stdout, "No valid device selected. Quitting...\n");
            device_manager_free(manager);
            return false;
        }

        /* User input is expected to be between 1 and dev_count, so we subtract 1 to get the zero-based index */
        device_manager_set_selected_device_index(manager, selected_dev_idx - 1);

        pcap_if_t *dev = device_manager_get_selected_device(manager);
        device_name = dev->name;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    sniff_handle = pcap_open_live(device_name, MAX_CAPLEN, PROMISC, 1000, errbuf);
    if (sniff_handle == NULL) {
        /* Clean error message */
        char *clean_err = errbuf;
        size_t dev_len = strlen(device_name);

        if (strncmp(clean_err, device_name, dev_len) == 0 && clean_err[dev_len] == ':') {
            clean_err += dev_len + 1;
            if (*clean_err == ' ') {
                clean_err++;  /* Skip the space after the colon */
            }
        }

        fprintf(stderr, "Error: Couldn't open device '%s' - %s\n", device_name, clean_err);

        device_manager_free(manager);  /* Won't throw an error if manager is NULL */
        return false;
    }

    fprintf(stdout, "\nMode: Live capture on device '%s'. Press Ctrl+C to stop.\n\n", device_name);
    ui_print_packet_separator();

    /* Use -1 to sniff until an error occurs */
    pcap_loop(sniff_handle, -1, process_packet, NULL);

    fprintf(stdout, "Sniffing session closed.\n");

    pcap_close(sniff_handle);
    device_manager_free(manager);  /* Won't throw an error if manager is NULL */

    return true;
}
