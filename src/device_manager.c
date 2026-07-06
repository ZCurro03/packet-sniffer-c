#include <stdio.h>
#include <stdlib.h>
#include "../include/device_manager.h"

struct _DeviceManager {
    pcap_if_t *alldevs;
    pcap_if_t *selected_dev;
    size_t dev_count;
    size_t selected_dev_idx;
};

DeviceManager* device_manager_init() {
    DeviceManager *manager = (DeviceManager *) malloc(sizeof(DeviceManager));
    if (!manager) {
        fprintf(stderr, "Error allocating memory for DeviceManager.\n");
        return NULL;
    }

    manager->alldevs = NULL;
    manager->selected_dev = NULL;
    manager->dev_count = 0;
    manager->selected_dev_idx = 0;

    fprintf(stdout, "Initializing DeviceManager and retrieving available devices...\n");

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
	if (pcap_findalldevs(&manager->alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't find available devices: %s\n", errbuf);
        free(manager);
        return NULL;
    }

    pcap_if_t *dev = manager->alldevs;
    while (dev != NULL) {
        manager->dev_count++;
        dev = dev->next;
    }

    fprintf(stdout, "DeviceManager initialized successfully. Available devices retrieved.\n");

    return manager;
}

void device_manager_free(DeviceManager *manager) {
    if (manager) {
        if (manager->alldevs) {
            pcap_freealldevs(manager->alldevs);
        }
        free(manager);
    }
}

pcap_if_t* device_manager_get_all_devices(DeviceManager *manager) {
    if (!manager) {
        return NULL;
    }
    return manager->alldevs;
}

size_t device_manager_get_device_count(DeviceManager *manager) {
    if (!manager) {
        return 0;
    }
    return manager->dev_count;
}

size_t device_manager_get_selected_device_index(DeviceManager *manager) {
    if (!manager) {
        return 0;
    }
    return manager->selected_dev_idx;
}

bool device_manager_set_selected_device_index(DeviceManager *manager, size_t index) {
    if (!manager || index >= manager->dev_count) {
        return false;
    }

    /* Update selected device on the go */
    manager->selected_dev = manager->alldevs;
    manager->selected_dev_idx = 0;
    while (manager->selected_dev != NULL && manager->selected_dev_idx < index) {
        manager->selected_dev = manager->selected_dev->next;
        manager->selected_dev_idx++;
    }

    return true;
}

pcap_if_t* device_manager_get_selected_device(DeviceManager *manager) {
    if (!manager) {
        return NULL;
    }
    return manager->selected_dev;
}
