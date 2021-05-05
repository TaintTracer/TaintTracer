#include "NativeMethodSink.h"
#include <android/logging.h>
#include <debugger/ELFImage.h>
#include <debugger/InstructionAnalyzer.h>

NativeMethodSink::NativeMethodSink(ELFImage &image, const std::string &symbol_name,
                                   TaintValues tainted_values)
                                   : GenericNativeSink(std::move(tainted_values))
                                   , ImageBreakpoints(BreakpointReason::TAINT_SINK_FUNCTION) {
    // Set breakpoints on the entry of the function
    breakpoint_offsets_.push_back(image.get_symbol_region(symbol_name).start_address);
}
