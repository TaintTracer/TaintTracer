#pragma once

#include <string>
#include <debugger/breakpoint/BreakpointHandler.h>
class Debugger;
class Process;

enum class TaintKind {
    UNDEFINED,
    LOCATION,
    PHONE_NUMBER,
    CALL_LOG,
    CONTACTS,
    SMS,
    MICROPHONE,
    CAMERA,
    BODY_SENSORS,
    EXTERNAL_FILES
};

class TaintSource {
private:
    const std::string label_;    ///< Human readable taint source label
    // const TaintKind kind_;
protected:
    TaintSource() = default;
public:
    TaintSource(std::string label);
    virtual const char *get_name() const;
};
