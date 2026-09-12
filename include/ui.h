#ifndef UI_H
#define UI_H

#include <stdbool.h>
#include <pcap/pcap.h>


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Displays the list of available network devices to the user.
 * @param alldevs Pointer to the list of available devices.
 */
void ui_display_available_devices(pcap_if_t *alldevs);

/**
 * Prompts the user to select a network device from the list.
 * @param dev_count The number of available devices.
 * @return The index of the selected device (1-based). Returns 0 if no valid selection is made.
 */
size_t ui_prompt_for_device_selection(size_t dev_count);

#endif /* UI_H */
