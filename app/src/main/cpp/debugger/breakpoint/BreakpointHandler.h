#pragma once

class Process;
class Debugger;

class BreakpointHandler {
public:
    virtual ~BreakpointHandler() = default;
    virtual void on_breakpoint(Debugger &d, Process &p) = 0;
};
