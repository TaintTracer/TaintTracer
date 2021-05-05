#pragma once

#include "TaintSource.h"

/**
 * Taint information obtained by directly invoking a system call e.g. Binder IPC
 */
class SyscallSource : TaintSource {
};
