#ifndef UI_H
#define UI_H

#include <stdbool.h>
#include <pcap/pcap.h>


/**********
 * Macros *
 **********/

#define PACKET_SEPARATOR_LENGTH 74      /* Length of the packet separator line */

#define UI_COLOR_RED     "\033[31m"     /* Red color ANSI Escape Code */
#define UI_COLOR_YELLOW  "\033[33m"     /* Yellow color ANSI Escape Code */
#define UI_COLOR_CYAN    "\033[36m"     /* Cyan color ANSI Escape Code */
#define UI_COLOR_GREY    "\033[90m"     /* Grey color ANSI Escape Code */
#define UI_COLOR_RESET   "\033[0m"      /* Reset color ANSI Escape Code */

/* UI Tree View Elements (UTF-8 Hex) */
#define TREE_PROT " \xE2\x94\x9C\xE2\x94\x80"                   /* " ├─" */
#define TREE_ITEM " \xE2\x94\x82   \xE2\x94\x9C\xE2\x94\x80"    /* " │   ├─" */
#define TREE_LAST " \xE2\x94\x82   \xE2\x94\x94\xE2\x94\x80"    /* " │   └─" */
#define PACKET_SEPARATOR "\xE2\x94\x81"                         /* "━" */


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Configures the terminal to hide ECHOCTL characters (like Ctrl+C).
 */
void ui_configure_terminal(void);

/**
 * Restores the terminal settings to their original state.
 */
void ui_restore_terminal(void);

/**
 * Displays the title header of the application.
 */
void ui_print_header(void);

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

/**
 * Prints a separator line to visually separate packets in the output.
 */
void ui_print_packet_separator(void);

#endif /* UI_H */
