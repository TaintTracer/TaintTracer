#pragma once

#include "GenericNativeSink.h"
#include <string>
#include <debugger/breakpoint/ImageBreakpoints.h>
class ELFImage;

class NativeMethodSink : public GenericNativeSink, public ImageBreakpoints{
public:
    NativeMethodSink(ELFImage& image, const std::string& symbol_name, TaintValues tainted_values);
    void on_breakpoint(Debugger &d, Process &p) override {
        return GenericNativeSink::on_breakpoint(d, p);
    }
};
