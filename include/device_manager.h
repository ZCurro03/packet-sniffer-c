#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <stdbool.h>
#include <pcap/pcap.h>

typedef struct _DeviceManager DeviceManager;

DeviceManager* device_manager_init();

void device_manager_free(DeviceManager *manager);

pcap_if_t* device_manager_get_all_devices(DeviceManager *manager);

size_t device_manager_get_device_count(DeviceManager *manager);

size_t device_manager_get_selected_device_index(DeviceManager *manager);

bool device_manager_set_selected_device_index(DeviceManager *manager, size_t index);

pcap_if_t* device_manager_get_selected_device(DeviceManager *manager);

#endif /* DEVICE_MANAGER_H */
