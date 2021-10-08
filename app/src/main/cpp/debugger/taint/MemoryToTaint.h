#pragma once

#include "TaintEvent.h"
#include "AnnotatedAddressSpace.h"

class MemoryToTaint {
public:
    MemoryToTaint(const std::optional<TaintEvent> &taintTag, const MemoryRegion &memoryRegion);

    std::optional<TaintEvent> taint_tag;
    MemoryRegion memory_region;
};
