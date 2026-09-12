#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include <stdbool.h>


/********************************
 * Public functions declaration *
 ********************************/

/**
 * Sets a signal handler for the specified signal. The function will block all signals
 * during the handler's execution to avoid interruptions.
 * @param signum The signal number to handle.
 * @param handler The function to handle the signal.
 * @return true if the signal handler was set successfully, false otherwise.
 */
bool set_signal_handler(int signum, void (*handler)(int));

#endif /* SIGNAL_HANDLER_H */