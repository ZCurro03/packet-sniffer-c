#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "../include/signal_handler.h"


/***********************************
 * Public functions implementation *
 ***********************************/

bool set_signal_handler(int signum, void (*handler)(int)) {
    struct sigaction action = {0};

    /* Block all signals during the handler's execution to avoid interruptions */
    sigfillset(&(action.sa_mask));
    action.sa_handler = handler;
    action.sa_flags = 0;

    if (sigaction(signum, &action, NULL) == -1) {
        perror("sigaction");
        return false;
    }

    return true;
}
