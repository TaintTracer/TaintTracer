#include "PendingProcessEvents.h"
#include <fmt/format.h>

bool PendingProcessEvents::has_event_for_pid(pid_t pid) {
    return events_.find(pid) != events_.end();
}

std::optional<WaitEvent> PendingProcessEvents::dequeue(std::optional<pid_t> pid_opt) {
    if (order_.empty()) {
        return std::nullopt;
    }
    if (pid_opt) {
        auto order_it = std::find(order_.begin(), order_.end(), *pid_opt);
        if (order_it == order_.end()) {
            return std::nullopt;
        }
        auto it = events_.find(*pid_opt);
        if (it == events_.end()) {
            throw std::runtime_error("Invariant violated: no matching element found in map");
        }
        WaitEvent res = it->second;
        events_.erase(it); // Remove from map
        order_.erase(order_it); // Remove from queue
        assert(res.get_pid() == *pid_opt);
        return res;
    } else {
        pid_t pid = order_.front();
        auto it = events_.find(pid);
        if (it == events_.end()) {
            throw std::runtime_error("Invariant violated: no matching element found in map");
        }
        WaitEvent res = it->second;
        events_.erase(it); // Remove from map
        order_.pop_front(); // Remove from queue
        return res;
    }
}

void PendingProcessEvents::enqueue(WaitEvent event) {
    auto pid = event.get_pid();
    auto [it, inserted] = events_.emplace(pid, std::move(event));
    if (!inserted) {
        throw std::runtime_error(fmt::format("Tried to enqueue event for pid {} while another event is still pending", pid));
    }
    order_.push_back(pid);
    assert(has_event_for_pid(pid));
}
