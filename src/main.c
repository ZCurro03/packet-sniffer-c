#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
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


/*******************
 * Data structures *
 *******************/

typedef struct {
    const char *pcap_file;  /* Path to the pcap file for offline analysis */
    const char *target_dev; /* Name of the network interface for live capture */
    int num_packets;        /* Number of packets to capture (-1 for unlimited) */
    bool is_valid;          /* Flag indicating if the arguments are valid */
} CLIArgs;


/*********************************
 * Private functions declaration *
 *********************************/

/**
 * Handles the SIGINT (Ctrl+C) signal to interrupt the capture loop.
 * @param signum Number of the received signal.
 */
void handle_sigint(int signum);

/**
 * Parses command-line arguments to determine the target device, the pcap file and the number of packets to capture.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return The parsed command-line arguments.
 */
CLIArgs parse_arguments(int argc, char *argv[]);

/**
 * Prints the usage information for the program.
 * @param prog_name The name of the program.
 */
void print_usage(const char *prog_name);

/**
 * Runs a live packet capture session, either on the specified device or in interactive mode.
 * @param target_dev The name of the device to capture on, or NULL for interactive mode.
 * @param num_packets The number of packets to capture, or -1 for unlimited.
 * @return true if the capture was successful, false otherwise.
 */
bool run_live_capture(const char *target_dev, int num_packets);

/**
 * Runs an offline packet capture session from the specified pcap file.
 * @param pcap_file The name of the pcap file to analyze.
 * @param num_packets The number of packets to capture, or -1 for unlimited.
 * @return true if the capture was successful, false otherwise.
 */
bool run_offline_capture(const char *pcap_file, int num_packets);


/********
 * Main *
 ********/

int main(int argc, char *argv[]) {
    if (!set_signal_handler(SIGINT, handle_sigint)) {
        exit(EXIT_FAILURE);
    }

    ui_configure_terminal();
    atexit(ui_restore_terminal);  /* Ensure terminal settings are restored on exit */

    CLIArgs args = parse_arguments(argc, argv);
    if (!args.is_valid) {
        exit(EXIT_FAILURE);
    }

    ui_print_header();

    if (args.pcap_file) {
        if (!run_offline_capture(args.pcap_file, args.num_packets)) {
            exit(EXIT_FAILURE);
        }
    } else {
        if (!run_live_capture(args.target_dev, args.num_packets)) {
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

CLIArgs parse_arguments(int argc, char *argv[]) {
    CLIArgs args = { .target_dev = NULL, .pcap_file = NULL, .num_packets = -1, .is_valid = true };

    opterr = 0;  /* Disable default error messages */

    int opt;
    while (args.is_valid && (opt = getopt(argc, argv, ":i:r:n:h")) != -1) {
        switch (opt) {
            case 'i':
                args.target_dev = optarg;
                break;
            case 'r':
                args.pcap_file = optarg;
                break;
            case 'n':
                char *endptr;
                errno = 0;
                long val = strtol(optarg, &endptr, 10);

                /* Validation checks for the -n option:
                 * 1. optarg == endptr: No digits found.
                 * 2. *endptr != '\0': There are garbage characters at the end (e.g., "100abc").
                 * 3. errno == ERANGE: Overflow of the long type.
                 * 4. Strict range: Greater than 0 and less than or equal to INT_MAX.
                 */
                if (optarg == endptr || *endptr != '\0' || errno == ERANGE || val <= 0 || val > INT_MAX) {
                    fprintf(stderr, "Error: Option -n requires a positive integer between 1 and %d.\n", INT_MAX);
                    args.is_valid = false;
                } else {
                    args.num_packets = (int)val;
                }            
                break;
            case ':':
                fprintf(stderr, "Error: Option -%c requires an argument.\n", optopt);
                args.is_valid = false;
                break;
            case '?':
                fprintf(stderr, "Error: Unknown option '-%c'.\n", optopt);
                args.is_valid = false;
                break;
            case 'h':
            default:
                args.is_valid = false;
                return args;
        }
    }

    if (args.is_valid && optind < argc) {
        fprintf(stderr, "Error: Unexpected positional arguments.\n");
        args.is_valid = false;
    }

    if (args.is_valid && args.target_dev != NULL && args.pcap_file != NULL) {
        fprintf(stderr, "Error: Options -i and -r are mutually exclusive.\n");
        args.is_valid = false;
    }

    if (!args.is_valid) {
        print_usage(argv[0]);
    }

    return args;
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [-i interface] [-r pcap_file] [-n num_packets]\n", prog_name);
    fprintf(stderr, "  -i <interface>   Listen on the specified interface\n");
    fprintf(stderr, "  -r <pcap_file>   Read packets from a pcap file\n");
    fprintf(stderr, "  -n <num_packets> The number of packets to capture (default: unlimited)\n");
    fprintf(stderr, "  -h               Show this help message\n");
}

bool run_live_capture(const char *target_dev, int num_packets) {
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

    /* Use num_packets = -1 to sniff until an error occurs */
    pcap_loop(sniff_handle, num_packets, process_packet, NULL);

    fprintf(stdout, "Sniffing session closed.\n");

    pcap_close(sniff_handle);
    sniff_handle = NULL;
    device_manager_free(manager);  /* Won't throw an error if manager is NULL */

    return true;
}

bool run_offline_capture(const char *pcap_file, int num_packets) {
    if (!pcap_file) {
        fprintf(stderr, "Error: No pcap file specified for offline capture.\n");
        return false;
    }

    fprintf(stdout, "Mode: Offline analysis from file '%s'.\n\n", pcap_file);

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    sniff_handle = pcap_open_offline(pcap_file, errbuf);
    if (sniff_handle == NULL) {
        /* Clean error message */
        char *clean_err = errbuf;
        size_t filename_len = strlen(pcap_file);

        if (strncmp(clean_err, pcap_file, filename_len) == 0 && clean_err[filename_len] == ':') {
            clean_err += filename_len + 1;
            if (*clean_err == ' ') {
                clean_err++;  /* Skip the space after the colon */
            }
        }

        fprintf(stderr, "Error: Couldn't open pcap file '%s' - %s\n", pcap_file, clean_err);
        return false;
    }

    ui_print_packet_separator();

    /* Use num_packets = -1 to sniff until EOF is reached or an error occurs */
    if (pcap_loop(sniff_handle, num_packets, process_packet, NULL) < 0) {
        fprintf(stderr, "Error during pcap analysis: %s\n", pcap_geterr(sniff_handle));
        pcap_close(sniff_handle);
        return false;
    }

    fprintf(stdout, "Offline analysis finished.\n");

    pcap_close(sniff_handle);
    sniff_handle = NULL;

    return true;
}
