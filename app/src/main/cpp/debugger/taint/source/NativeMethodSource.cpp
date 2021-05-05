#include "NativeMethodSource.h"
#include <debugger/ELFImage.h>
#include <debugger/Process.h>
#include <debugger/memory/MemoryMap.h>
#include <android/logging.h>

NativeMethodSource::NativeMethodSource(ELFImage& image,
                                       const std::string &symbol_name,
                                       TaintValues tainted_values)
                                       : GenericNativeSource(std::move(tainted_values))
                                       , ImageBreakpoints(BreakpointReason::TAINT_SOURCE_FUNCTION) {
    // Get all return statements of the specified method by symbol name
    auto region = image.get_symbol_region(symbol_name);
    auto region_ptr = image.mapped_image_base() + region.start_address;
    LOGD("Analyzing native method source %s of image %s (+0x%" PRIx64 ") with size 0x%" PRIx64,
            symbol_name.c_str(), image.get_path().c_str(), region.start_address, region.size());
    auto method_analysis = InstructionAnalyzer::get_instance().analyze_capstone(region_ptr, region.size(), region.start_address);
    for (size_t i = 0; i < method_analysis.size(); i++) {
        if (method_analysis.is_return(i))
            breakpoint_offsets_.push_back(method_analysis.instruction_address(i));
    }
}

