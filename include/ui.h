#ifndef UI_H
#define UI_H

#include <stdbool.h>
#include <pcap/pcap.h>

void ui_display_available_devices(pcap_if_t *alldevs);

size_t ui_prompt_for_device_selection(size_t dev_count);

#endif /* UI_H */
