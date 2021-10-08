import re
from dataclasses import dataclass

@dataclass
class Event:
    signal: str
    label: str

of = open("aggregate.csv", "w+")
of.write("signal,label\n");
info = None

r_start = re.compile(".*Event received .* with status (0x[0-9a-f]+)$")
r_syscall = re.compile(".*System call (entry|exit) \(.*\): (\w+)")
r_clean = re.compile(".*Instruction @ pc tried to access clean memory")
r_tainted = re.compile(".*Instruction @ pc tried to access tainted memory")

def handle_line(line):
    global info
    if r_start.match(line):
        if info is not None:
            of.write("{},{}\n".format(info.signal, info.label))
        info = Event(r_start.search(line).group(1), "")
    if r_syscall.match(line):
        info.label = r_syscall.search(line).group(2)
    if r_clean.match(line):
        info.label = "Untainted"
    elif r_tainted.match(line):
        info.label = "Tainted"

for line in open("../../../log-demo-benchmark-single.txt"):
    handle_line(line)
