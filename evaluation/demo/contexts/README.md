# TaintDebugger evaluation
Each directory contains a logfile and graph of instructions that propagate tainted contact data.
Each directory corresponds to a different combination of source and sink types. For instance, the `java_native` directory corresponds to a source that obtains the tainted data from a Java implementation, which propagates to a native sink.

Each directory contains the following files:
- `log.txt`: Logs generated by our system.
- `taintevents.pdf`: Plot of events (instructions or system calls) that propagate tainted data. Each event that depends on tainted values that were written by other events has inbound edges from those dependent events.

## System configuration used for evaluation
* Hardware: Google Pixel 4 (MP1.0)
* Android version 10
* Android build number QQ1B.200105.004
* Android security patch level: January 1, 2020
* Google Play system update September 1, 2019
* Baseband version: g8150-00041-191016-B-5945070
* Kernel version: 4.14.111-ge58a32340f44-ab6027802

