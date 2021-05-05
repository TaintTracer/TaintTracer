#include "InstructionBreakpoint.h"
#include <vector>
#include <fmt/format.h>

InstructionBreakpointEntry::InstructionBreakpointEntry(BreakpointReason reason,
                                                       bool is_temporary_and_this_pid_only,
                                                       bool remove_at_next_stop,
                                                       std::optional<std::reference_wrapper<BreakpointHandler>> handler)
        : reason(reason)
        , is_temporary_and_this_pid_only(is_temporary_and_this_pid_only)
        , remove_at_next_stop(remove_at_next_stop)
        , handler(std::move(handler)) {
    assert(!(is_temporary_and_this_pid_only ^ remove_at_next_stop));
}

InstructionBreakpoint::InstructionBreakpoint(const std::array<unsigned char, 4> orig_ins,
                                             const std::array<unsigned char, 4> bp_ins)
    : orig_ins(orig_ins)
    , bp_ins(bp_ins)  {
    if (std::equal(this->orig_ins.begin(), this->orig_ins.end(), this->bp_ins.begin())) {
        std::runtime_error("Setting breakpoint on an existing breakpoint");
    }
    assert(is_empty());
}

bool InstructionBreakpoint::is_enabled() const {
    return enabled_;
}

std::optional<BreakpointReason> InstructionBreakpoint::should_handle(pid_t trapped_pid) {
    if (permanent_breakpoint_) {
        return permanent_breakpoint_->reason;
    } else if (auto it = temporary_breakpoints_.find(trapped_pid); it != temporary_breakpoints_.end()) {
        return it->second.reason;
    }
    return {};
}

bool InstructionBreakpoint::toggle_enabled() {
    enabled_ = !enabled_;
    if (enabled_) {
        enabled_count_++;
    }
    return enabled_;
}

std::vector<std::reference_wrapper<InstructionBreakpointEntry>>
InstructionBreakpoint::get_breakpoints(pid_t pid) {
    auto res = std::vector<std::reference_wrapper<InstructionBreakpointEntry>> {};
    auto it = temporary_breakpoints_.find(pid);
    if (it != temporary_breakpoints_.end()) {
        res.emplace_back(it->second);
    }
    if (permanent_breakpoint_) {
        res.emplace_back(std::ref(*permanent_breakpoint_));
    }
    return res;
}

void InstructionBreakpoint::add_entry(pid_t pid, InstructionBreakpointEntry entry) {
    if (entry.is_temporary_and_this_pid_only) {
        auto it = temporary_breakpoints_.find(pid);
        if (it != temporary_breakpoints_.end()) {
            throw std::runtime_error(fmt::format("Failed to add temporary breakpoint entry: an existing entry for pid {} already exists", pid));
        }
        temporary_breakpoints_.emplace_hint(it, std::piecewise_construct,
                                            std::forward_as_tuple(pid),
                                            std::forward_as_tuple(std::move(entry))
        );
    } else {
        if (permanent_breakpoint_) {
            throw std::runtime_error("Failed to add permanent breakpoint entry: an entry already exists");
        }
        permanent_breakpoint_.emplace(std::move(entry));
    }
}

void InstructionBreakpoint::remove_temporary_entry(pid_t pid) {
    auto it = temporary_breakpoints_.find(pid);
    if (it == temporary_breakpoints_.end()) {
        throw std::runtime_error(fmt::format("Failed to remove temporary breakpoint entry: entry for pid {} does not exist", pid));
    }
    temporary_breakpoints_.erase(it);
}

void InstructionBreakpoint::remove_permanent_entry() {
    if (!permanent_breakpoint_) {
        throw std::runtime_error("Failed to remove permanent breakpoint entry: entry does not exist");
    }
    permanent_breakpoint_ = std::nullopt;
}

bool InstructionBreakpoint::contains_temporary_entry_for_pid(pid_t pid) {
    auto it = temporary_breakpoints_.find(pid);
    return it != temporary_breakpoints_.end();
}

bool InstructionBreakpoint::contains_permanent_entry() {
    return permanent_breakpoint_.has_value();
}

std::vector<pid_t> InstructionBreakpoint::list_temporary_entries() {
    auto res = std::vector<pid_t> {};
    res.reserve(temporary_breakpoints_.size());
    for (auto it = temporary_breakpoints_.begin(); it != temporary_breakpoints_.end(); it++) {
        res.push_back(it->first);
    }
    return res;
}

bool InstructionBreakpoint::is_empty() {
    return !permanent_breakpoint_ && temporary_breakpoints_.empty();
}
