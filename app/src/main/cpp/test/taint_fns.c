#include "taint_fns.h"

/* Tainted methods */
int source_ret9() {
    return 9;
}

int source_ret42() {
    return 42;
}

/* Sinks */
void sink(int x) {}
