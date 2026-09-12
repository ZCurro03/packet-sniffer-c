#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <stdbool.h>
#include <pcap/pcap.h>


/*************************************
 * Opaque data structure declaration *
 *************************************/

/**
 * Opaque data structure representing a device manager.
 * This structure is used to manage and interact with network devices.
 * It contains information about all available devices, the currently selected device, and the total number of devices.
 */
typedef struct _DeviceManager DeviceManager;


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Initializes a new DeviceManager instance.
 * This function allocates memory for a DeviceManager structure, retrieves the list of available
 * network devices, and initializes the internal state.
 * @return A pointer to the newly created DeviceManager instance, or NULL if the initialization fails.
 */
DeviceManager* device_manager_init();

/**
 * Frees the memory allocated for a DeviceManager instance.
 * This function releases the resources associated with the DeviceManager, including the list of
 * available devices.
 * @param manager A pointer to the DeviceManager instance to be freed.
 */
void device_manager_free(DeviceManager *manager);

/**
 * Retrieves the list of all available network devices managed by the DeviceManager.
 * @param manager A pointer to the DeviceManager instance.
 * @return A pointer to the list of available devices (pcap_if_t), or NULL if the manager is NULL.
 */
pcap_if_t* device_manager_get_all_devices(DeviceManager *manager);

/**
 * Retrieves the total number of available network devices managed by the DeviceManager.
 * @param manager A pointer to the DeviceManager instance.
 * @return The total number of available devices, or 0 if the manager is NULL.
 */
size_t device_manager_get_device_count(DeviceManager *manager);

/**
 * Retrieves the index of the currently selected network device managed by the DeviceManager.
 * @param manager A pointer to the DeviceManager instance.
 * @return The index of the selected device, or 0 if the manager is NULL.
 */
size_t device_manager_get_selected_device_index(DeviceManager *manager);

/**
 * Sets the index of the currently selected network device managed by the DeviceManager.
 * This function updates the selected device based on the provided index.
 * @param manager A pointer to the DeviceManager instance.
 * @param index The index of the device to be selected (0-based).
 * @return true if the selected device index was successfully set, false otherwise (e.g., if
 * the manager is NULL or the index is out of bounds).
 */
bool device_manager_set_selected_device_index(DeviceManager *manager, size_t index);

/**
 * Retrieves the currently selected network device managed by the DeviceManager.
 * @param manager A pointer to the DeviceManager instance.
 * @return A pointer to the selected device (pcap_if_t), or NULL if the manager is NULL or no
 * device is selected.
 */
pcap_if_t* device_manager_get_selected_device(DeviceManager *manager);

#endif /* DEVICE_MANAGER_H */
