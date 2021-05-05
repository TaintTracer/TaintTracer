#pragma once

#include <variant>
#include <chrono>
#include <vector>
#include <debugger/taint/execution/ExecutionUnit.h>
#include <optional>

class TaintSource;
class TaintEvent;

std::optional<std::reference_wrapper<std::ofstream>> get_plot_ofstream();

/**
 * Logged event where the process has requested or propagated tainted information from the system.
 */
class TaintEvent {
private:
    size_t new_taint_id();
public:
    /**
     * List of taint events that influenced this taint event
     * It can either be a taint source, or event(s) that eventually lead to a TaintSource.
     * We keep a list of TaintEvents to support a single instruction propagating different kinds
     * of sources at once. This may happen if e.g. every byte of a word contains tainted information
     * from different sources
     */
    using var_t = std::variant<std::reference_wrapper<const TaintSource>, std::vector<TaintEvent>>;
    var_t prev_events_;
    std::shared_ptr<ExecutionUnit> execution_unit_; // TODO: Change shared_ptr to unique_ptr
    std::chrono::system_clock::time_point timestamp_;
    /**
     * Identifier of a taint event assigned by a monotonic counter
     * This identifier is copied when copy constructing an instance.
     * This may be used to order events or assigning a node to each unique id when plotting
     */
    size_t taint_id_;

    TaintEvent(const TaintSource& taint_source, std::shared_ptr<ExecutionUnit> execution_unit) : TaintEvent(var_t(std::ref(taint_source)), std::move(execution_unit)) {}
    TaintEvent(std::vector<TaintEvent> prev_events, std::shared_ptr<ExecutionUnit> execution_unit) : TaintEvent(var_t(prev_events), std::move(execution_unit)) {}
    TaintEvent(var_t prev_events, std::shared_ptr<ExecutionUnit> execution_unit);

    /**
     * Plot to the default file stream
     */
    void plot() const;
    void plot(std::ostream &out, const TaintEvent *child_event = 0) const;
};
