#include "TaintEvent.h"
#include <fmt/format.h>
#include <android/logging.h>
#include <fstream>
#include <android/Debugging.h>
#include <debugger/Debugger.h>
#include <debugger/procfs/Process.h>

size_t TaintEvent::new_taint_id() {
    static size_t monotonic_counter = 0;
    return monotonic_counter++;
}

TaintEvent::TaintEvent(var_t prev_events, std::shared_ptr<ExecutionUnit> execution_unit)
        : prev_events_(std::move(prev_events)), execution_unit_(std::move(execution_unit)),
          timestamp_(std::chrono::system_clock::now()),
          taint_id_(new_taint_id()) {
    // plot();
}

void TaintEvent::plot(std::ostream &out, const TaintEvent *child_event) const {
    if (!child_event) {
        // Plot strict graph to collapse duplicate edges caused by deep copying TaintEvents
        out << "strict digraph G { node [shape=box]; ";
    }

    out << fmt::format(R"x("{}"[label="{} ({})"];)x", taint_id_, execution_unit_->str(), taint_id_);
    if (child_event) {
        out << fmt::format(R"("{}" -> "{}";)", taint_id_, child_event->taint_id_);
    }

    if (std::holds_alternative<std::vector<TaintEvent>>(prev_events_)) {
        for (const auto &prev_e : std::get<std::vector<TaintEvent>>(prev_events_)) {
            prev_e.plot(out, this);
        }
    }

    if (!child_event) {
        out << "}";
    }
}

void TaintEvent::plot() const {
    if (auto file_opt = get_plot_ofstream()) {
        auto &file = file_opt->get();
        plot(file);
        file.flush();
    } else {
        LOGW("Failed to open default file to write plot data. Skipping plot()");
    }
}

std::optional<std::reference_wrapper<std::ofstream>> get_plot_ofstream() {
    static auto f = std::ofstream(get_data_dir(get_package_name(get_uid_of_pid(Debugger::get_instance().get_root_pid()))) + "/plot");
    if (f) {
        return std::ref(f);
    } else {
        return {};
    }
}
