#include <stdio.h>
#include "../include/ui.h"
#include "../include/icmpv6.h"


/***********************************
 * Public functions implementation *
 ***********************************/

void process_icmpv6_message(const u_char *message, uint32_t length) {
    if (!message || length < ICMPV6_HEADER_LEN) {
        fprintf(stderr, "Error: invalid or truncated ICMPv6 message.\n");
        return;
    }

    const Icmpv6Header *icmpv6_header = (const Icmpv6Header *)message;

    fprintf(stdout, "%s ICMPv6\n", TREE_PROT);

    (void)icmpv6_header;  /* Suppress unused variable warning */
    fprintf(stdout, "To be implemented.\n");
}
