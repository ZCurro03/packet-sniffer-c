#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include <stdbool.h>

bool set_signal_handler(int signum, void (*handler)(int));

#endif /* SIGNAL_HANDLER_H */