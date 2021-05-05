#pragma once

#include "WaitEvent.h"
#include <sys/types.h>
#include <map>
#include <list>

class PendingProcessEvents {
private:
    // Invariant: all keys in order_ must be present in events_, and vice-versa
    std::map<pid_t, WaitEvent> events_;
    std::list<pid_t> order_;

public:
    bool has_event_for_pid(pid_t pid);
    std::optional<WaitEvent> dequeue(std::optional<pid_t> pid = {});
    void enqueue(WaitEvent event);
};
