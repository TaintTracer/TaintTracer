##
# Find all instructions that touch a given memory region of interest
#
# Copy the contents of this script to an interactive LLDB session
# using the `script` command
##
cmds = """process handle SIGSEGV --pass false --stop true --notify true
b -o true -n 'android::CursorWindow::createFromParcel(android::Parcel*, android::CursorWindow**)'
c

b -o true -a `(void())mmap`+8  # After svc instruction
c

e unsigned long $addr = $x0
e unsigned long $len = $x1
e unsigned long $prot = $x2
e (int) mprotect($addr, $len, 0)
c""".split('\n')

dbg = lldb.debugger
repl = dbg.GetCommandInterpreter()

listener = lldb.SBListener('guard_page_loop')
proc = dbg.GetSelectedTarget().GetProcess()
broadcaster = proc.GetBroadcaster()
broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
event = lldb.SBEvent()

def wait(state = lldb.eStateStopped):
    while True:
        if not listener.WaitForEventForBroadcasterWithType(3, broadcaster, lldb.SBProcess.eBroadcastBitStateChanged, event):
            print("Waiting for process event...")
            continue
        if not lldb.SBProcess.EventIsProcessEvent(event):
            print("Ignoring non-process event")
            continue
        if event.GetType() != lldb.SBProcess.eBroadcastBitStateChanged:
            print ("Ignoring event that isn't eBroadcastBitStateChanged")
            continue
        event_state = lldb.SBProcess.GetStateFromEvent(event)
        if event_state == lldb.eStateInvalid or event_state == lldb.eStateRunning:
            continue
        if event_state == lldb.eStateExited:
            raise RuntimeError("Process exited!")
        elif event_state == state:
            return event_state
        print("Ignoring state {}".format(event_state))
        proc.Continue()

def exec_repl(cmd, f = None):
    res = lldb.SBCommandReturnObject()
    repl.HandleCommand(cmd, res)
    if not res.Succeeded():
        raise RuntimeError("Command {} failed: {}".format(cmd, res.GetError()))
    elif f is not None:
        f.write(res.GetOutput() + '\n')

for cmd in cmds:
    if cmd == "":
        wait()
    else:
        exec_repl(cmd)

trace_file = open("trace.txt", "w", buffering=1)
while True:
    print("Calling wait")
    wait()
    t = proc.GetSelectedThread()
    s_reason = t.GetStopReason()
    print("Stop reason: {}".format(s_reason))
    if s_reason == lldb.eStopReasonSignal:
        print("Process stopped!")
        exec_repl("disass -C 8 --pc", trace_file)
        exec_repl("bt", trace_file)
        stream = lldb.SBStream()
        event.GetDescription(stream)
        print('Event description:', stream.GetData())
        print("Restoring original perms")
        exec_repl("e (int) mprotect($addr, $len, $prot)")  # Restore original mprotect perms
        print("Single step with original perms")
        t.StepInstruction(False)
        wait()
        if t.GetStopReason() != lldb.eStopReasonPlanComplete:
            raise RuntimeError("Unexpected stop reason after single stepping: {}".format(t.GetStopReason()))
        print("Single step stop reason: {}".format(t.GetStopReason()))
        print("Revoking perms")
        exec_repl("e (int) mprotect($addr, $len, 0)")  # Restore original mprotect perms
        print("Continuing")
    else:
        print("Stopped without segfault. Got stop reason {}".format(s_reason))
        break
    if not proc.Continue().success:
        raise RuntimeError("Failed to continue process")
