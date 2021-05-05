#pragma once

#include <map>
#include <array>
#include <optional>
class NativeMethodSource;
class BreakpointHandler;

enum class BreakpointReason {
    UNKNOWN = 0,
    MEMORY_ACCESS,
    TAINT_SOURCE_FUNCTION,
    TAINT_SINK_FUNCTION,
    JUMP_INSTRUCTION,
    END_OF_ANALYZED_INSTRUCTION_BLOCK,
    TAINTPROP_BREAKPOINT_OPTIMIZER,
    TAINTPROP_BREAKPOINT_OPTIMIZER_STORE_CONDITIONAL,
};

struct InstructionBreakpointEntry {
    InstructionBreakpointEntry(BreakpointReason reason, bool is_temporary_and_this_pid_only,
                               bool remove_at_next_stop,
                               std::optional<std::reference_wrapper<BreakpointHandler>> handler);
    /**
     * Breakpoint metadata
     */
    const BreakpointReason reason;

    /**
     * Whether SIGTRAP events raised by this process of the inserted breakpoint should only be handled.
     * The breakpoint will be ignored if this flag is set and another process hits this breakpoint.
     * Additionally, the breakpoint should only be triggered once instead of having effect every
     * time the breakpoint is executed.
     */
    const bool is_temporary_and_this_pid_only;

    /**
     * Mark the breakpoint for removal when the process stops and when the process would handle this
     * breakpoint if this breakpoint would have been hit instead.
     */
    const bool remove_at_next_stop;
    /**
     * Handler to be invoked when the breakpoint is triggered
     */
    const std::optional<std::reference_wrapper<BreakpointHandler>> handler;
};

/*
 * An instruction breakpoint
 * optional TODO: For self-modifying code, we need to set memory breakpoints to clean up the overwritten
 *                InstructionBreakpoint instances
 */
class InstructionBreakpoint {
private:
    bool enabled_ = false;    ///< Whether the breakpoint is enabled
    int enabled_count_ = 0;  ///< Number of times the breakpoint has been enabled

    std::optional<InstructionBreakpointEntry> permanent_breakpoint_;

    /**
     * Map of temporary breakpoints
     * We allow one temporary breakpoint per process
     */
    std::map<pid_t, InstructionBreakpointEntry> temporary_breakpoints_;
public:
    InstructionBreakpoint(const std::array<unsigned char, 4> orig_ins,
                          const std::array<unsigned char, 4> bp_ins);
    const std::array<unsigned char, 4> orig_ins;
    const std::array<unsigned char, 4> bp_ins;

    bool is_enabled() const;

    /**
     * Toggle enabled state of the breakpoint
     * @return Enabled state of the breakpoint after toggling
     */
    bool toggle_enabled();

    std::vector<std::reference_wrapper<InstructionBreakpointEntry>> get_breakpoints(pid_t pid);

    void add_entry(pid_t pid, InstructionBreakpointEntry entry);

    void remove_temporary_entry(pid_t pid);

    void remove_permanent_entry();

    bool contains_temporary_entry_for_pid(pid_t pid);

    bool contains_permanent_entry();

    std::vector<pid_t> list_temporary_entries();

    /**
     * Returns true if the instruction breakpoint contains no entries, and is safe to be removed
     * from the physical page
     */
    bool is_empty();

    std::optional<BreakpointReason> should_handle(pid_t trapped_pid);

};

static_assert(sizeof(InstructionBreakpoint::orig_ins) == sizeof(InstructionBreakpoint::bp_ins),
        "Size of breakpoint instruction should be equal to the size of the original instruction");