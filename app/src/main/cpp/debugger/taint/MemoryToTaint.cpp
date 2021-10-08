#include "MemoryToTaint.h"

MemoryToTaint::MemoryToTaint(const std::optional<TaintEvent> &taintTag,
                             const MemoryRegion &memoryRegion) : taint_tag(taintTag),
                                                                 memory_region(memoryRegion) {}
