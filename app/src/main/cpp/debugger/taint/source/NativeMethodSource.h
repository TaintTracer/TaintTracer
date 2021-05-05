#pragma once

#include <debugger/breakpoint/ImageBreakpoints.h>
#include "GenericNativeSource.h"
class ELFImage;
struct MemoryMap;

/**
 * A method with an ELF symbol that is part of an executable image
 */
class NativeMethodSource : public GenericNativeSource, public ImageBreakpoints  {
private:
public:
    /**
     * Create a new source for which return instructions of the specified symbol in the ELF image
     * at which the specified registers and memory locations should be considered to contain tainted
     * information.
     */
    NativeMethodSource(ELFImage& image, const std::string& symbol_name, TaintValues tainted_values);

    void on_breakpoint(Debugger &d, Process &p) override {
        return GenericNativeSource::on_breakpoint(d, p);
    }

    /*
     * Breakpoints refer to the native method source by reference.
     * No relocating container types can hold elements of this type.
     */
    NativeMethodSource(const NativeMethodSource&) = delete;
    NativeMethodSource& operator=(const NativeMethodSource&) = delete;
    NativeMethodSource(NativeMethodSource&&) = delete;
    NativeMethodSource& operator=(NativeMethodSource&&) = delete;
};
