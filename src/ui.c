#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ui.h"

void ui_display_available_devices(pcap_if_t *alldevs) {
    fprintf(stdout, "Available devices:\n");

    if (!alldevs) {
        fprintf(stdout, "No available devices found.\n");
        return;
    }

    pcap_if_t *dev = NULL;
    size_t dev_count = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        fprintf(stdout, "  %ld. %s.\n", dev_count, dev->name);

        if (dev->description != NULL) fprintf(stdout, "  %s.\n", dev->description);
        else fprintf(stdout, "  No description available.\n");

        dev_count++;
    }
}

size_t ui_prompt_for_device_selection(size_t dev_count) {
    if (dev_count == 0) {
        fprintf(stdout, "No available devices to sniff on.\n");
        return 0;
    }

    long selected_dev_idx = 0;
    bool valid_idx = false;
    char idx_buff[16] = {0};
    do {
        fprintf(stdout, "Enter the index of the device to sniff on (between 1 and %ld) > ", dev_count);
        
        memset(idx_buff, 0, sizeof(idx_buff));
        if (fgets(idx_buff, sizeof(idx_buff), stdin) != NULL) {
            char *newline = strchr(idx_buff, '\n');
            if (newline == NULL) {
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
            } else {
                *newline = '\0';
            }
        } else {
            perror("Input error or EOF detected");
            return 0;
        }

        char *endptr = NULL;
        selected_dev_idx = strtol(idx_buff, &endptr, 10);

        valid_idx = endptr != idx_buff && *endptr == '\0' &&
            selected_dev_idx >= 1 && (size_t)selected_dev_idx <= dev_count;

        if (!valid_idx) {
            fprintf(stdout, "Invalid index. Please, try again.\n");
        }
    } while (!valid_idx);

    return (size_t)selected_dev_idx;
}
