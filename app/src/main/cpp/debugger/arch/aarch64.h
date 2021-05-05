#pragma once

#include <optional>
#include <capstone/arm64.h>
#include <debugger/taint/AnnotatedAddressSpace.h>
#include <aarch64-linux-android/asm/ptrace.h>
#include <array>
#include <libvex_basictypes.h>
#include <libvex_guest_offsets.h>
class Process;
struct SyscallEvent;

namespace aarch64 {
    constexpr size_t instruction_size = 4;
    constexpr uint8_t register_size = 8;
    constexpr std::array<unsigned char, 4> breakpoint_instruction {0, 0, 0x20, 0xd4}; // brk #0x0
    constexpr std::array<unsigned char, 4> syscall_instruction {0x01, 0, 0, 0xd4}; // svc #0
    constexpr std::array<unsigned char, 4> clear_exclusive_instruction {0x5f, 0x3f, 0x03, 0xd5}; // clrex
    constexpr uint32_t syscall_result_reg_offset = OFFSET_arm64_X0;
    constexpr uint32_t syscall_arg0_reg_offset = OFFSET_arm64_X0;
    constexpr uint32_t syscall_arg1_reg_offset = OFFSET_arm64_X1;
    constexpr uint32_t syscall_arg2_reg_offset = OFFSET_arm64_X2;
    constexpr uint32_t syscall_arg3_reg_offset = OFFSET_arm64_X3;
    constexpr uint32_t syscall_arg4_reg_offset = OFFSET_arm64_X4;
    constexpr uint32_t syscall_arg5_reg_offset = OFFSET_arm64_X5;

    /**
     * Generated using
     * curl -s https://raw.githubusercontent.com/hrw/syscalls-table/master/tables/syscalls-arm64 | \
     * perl -ne '/(\w+)\s+(\d+)/ && print $1." = ".$2.",\n"'
     */
    enum class syscall_number {
        accept = 202,
        accept4 = 242,
        acct = 89,
        add_key = 217,
        adjtimex = 171,
        bind = 200,
        bpf = 280,
        brk = 214,
        capget = 90,
        capset = 91,
        chdir = 49,
        chroot = 51,
        clock_adjtime = 266,
        clock_getres = 114,
        clock_gettime = 113,
        clock_nanosleep = 115,
        clock_settime = 112,
        clone = 220,
        clone3 = 435,
        close = 57,
        connect = 203,
        copy_file_range = 285,
        delete_module = 106,
        dup = 23,
        dup3 = 24,
        epoll_create1 = 20,
        epoll_ctl = 21,
        epoll_pwait = 22,
        eventfd2 = 19,
        execve = 221,
        execveat = 281,
        exit = 93,
        exit_group = 94,
        faccessat = 48,
        fadvise64 = 223,
        fallocate = 47,
        fanotify_init = 262,
        fanotify_mark = 263,
        fchdir = 50,
        fchmod = 52,
        fchmodat = 53,
        fchown = 55,
        fchownat = 54,
        fcntl = 25,
        fdatasync = 83,
        fgetxattr = 10,
        finit_module = 273,
        flistxattr = 13,
        flock = 32,
        fremovexattr = 16,
        fsconfig = 431,
        fsetxattr = 7,
        fsmount = 432,
        fsopen = 430,
        fspick = 433,
        fstat = 80,
        fstatfs = 44,
        fsync = 82,
        ftruncate = 46,
        futex = 98,
        get_mempolicy = 236,
        get_robust_list = 100,
        getcpu = 168,
        getcwd = 17,
        getdents64 = 61,
        getegid = 177,
        geteuid = 175,
        getgid = 176,
        getgroups = 158,
        getitimer = 102,
        getpeername = 205,
        getpgid = 155,
        getpid = 172,
        getppid = 173,
        getpriority = 141,
        getrandom = 278,
        getresgid = 150,
        getresuid = 148,
        getrlimit = 163,
        getrusage = 165,
        getsid = 156,
        getsockname = 204,
        getsockopt = 209,
        gettid = 178,
        gettimeofday = 169,
        getuid = 174,
        getxattr = 8,
        init_module = 105,
        inotify_add_watch = 27,
        inotify_init1 = 26,
        inotify_rm_watch = 28,
        io_cancel = 3,
        io_destroy = 1,
        io_getevents = 4,
        io_pgetevents = 292,
        io_setup = 0,
        io_submit = 2,
        io_uring_enter = 426,
        io_uring_register = 427,
        io_uring_setup = 425,
        ioctl = 29,
        ioprio_get = 31,
        ioprio_set = 30,
        kcmp = 272,
        kexec_file_load = 294,
        kexec_load = 104,
        keyctl = 219,
        kill = 129,
        lgetxattr = 9,
        linkat = 37,
        listen = 201,
        listxattr = 11,
        llistxattr = 12,
        lookup_dcookie = 18,
        lremovexattr = 15,
        lseek = 62,
        lsetxattr = 6,
        madvise = 233,
        mbind = 235,
        membarrier = 283,
        memfd_create = 279,
        migrate_pages = 238,
        mincore = 232,
        mkdirat = 34,
        mknodat = 33,
        mlock = 228,
        mlock2 = 284,
        mlockall = 230,
        mmap = 222,
        mount = 40,
        move_mount = 429,
        move_pages = 239,
        mprotect = 226,
        mq_getsetattr = 185,
        mq_notify = 184,
        mq_open = 180,
        mq_timedreceive = 183,
        mq_timedsend = 182,
        mq_unlink = 181,
        mremap = 216,
        msgctl = 187,
        msgget = 186,
        msgrcv = 188,
        msgsnd = 189,
        msync = 227,
        munlock = 229,
        munlockall = 231,
        munmap = 215,
        name_to_handle_at = 264,
        nanosleep = 101,
        newfstatat = 79,
        nfsservctl = 42,
        open_by_handle_at = 265,
        open_tree = 428,
        openat = 56,
        perf_event_open = 241,
        personality = 92,
        pidfd_open = 434,
        pidfd_send_signal = 424,
        pipe2 = 59,
        pivot_root = 41,
        pkey_alloc = 289,
        pkey_free = 290,
        pkey_mprotect = 288,
        ppoll = 73,
        prctl = 167,
        pread64 = 67,
        preadv = 69,
        preadv2 = 286,
        prlimit64 = 261,
        process_vm_readv = 270,
        process_vm_writev = 271,
        pselect6 = 72,
        ptrace = 117,
        pwrite64 = 68,
        pwritev = 70,
        pwritev2 = 287,
        quotactl = 60,
        read = 63,
        readahead = 213,
        readlinkat = 78,
        readv = 65,
        reboot = 142,
        recvfrom = 207,
        recvmmsg = 243,
        recvmsg = 212,
        remap_file_pages = 234,
        removexattr = 14,
        renameat = 38,
        renameat2 = 276,
        request_key = 218,
        restart_syscall = 128,
        rseq = 293,
        rt_sigaction = 134,
        rt_sigpending = 136,
        rt_sigprocmask = 135,
        rt_sigqueueinfo = 138,
        rt_sigreturn = 139,
        rt_sigsuspend = 133,
        rt_sigtimedwait = 137,
        rt_tgsigqueueinfo = 240,
        sched_get_priority_max = 125,
        sched_get_priority_min = 126,
        sched_getaffinity = 123,
        sched_getattr = 275,
        sched_getparam = 121,
        sched_getscheduler = 120,
        sched_rr_get_interval = 127,
        sched_setaffinity = 122,
        sched_setattr = 274,
        sched_setparam = 118,
        sched_setscheduler = 119,
        sched_yield = 124,
        seccomp = 277,
        semctl = 191,
        semget = 190,
        semop = 193,
        semtimedop = 192,
        sendfile = 71,
        sendmmsg = 269,
        sendmsg = 211,
        sendto = 206,
        set_mempolicy = 237,
        set_robust_list = 99,
        set_tid_address = 96,
        setdomainname = 162,
        setfsgid = 152,
        setfsuid = 151,
        setgid = 144,
        setgroups = 159,
        sethostname = 161,
        setitimer = 103,
        setns = 268,
        setpgid = 154,
        setpriority = 140,
        setregid = 143,
        setresgid = 149,
        setresuid = 147,
        setreuid = 145,
        setrlimit = 164,
        setsid = 157,
        setsockopt = 208,
        settimeofday = 170,
        setuid = 146,
        setxattr = 5,
        shmat = 196,
        shmctl = 195,
        shmdt = 197,
        shmget = 194,
        shutdown = 210,
        sigaltstack = 132,
        signalfd4 = 74,
        socket = 198,
        socketpair = 199,
        splice = 76,
        statfs = 43,
        statx = 291,
        swapoff = 225,
        swapon = 224,
        symlinkat = 36,
        sync = 81,
        sync_file_range = 84,
        syncfs = 267,
        sysinfo = 179,
        syslog = 116,
        tee = 77,
        tgkill = 131,
        timer_create = 107,
        timer_delete = 111,
        timer_getoverrun = 109,
        timer_gettime = 108,
        timer_settime = 110,
        timerfd_create = 85,
        timerfd_gettime = 87,
        timerfd_settime = 86,
        times = 153,
        tkill = 130,
        truncate = 45,
        umask = 166,
        umount2 = 39,
        uname = 160,
        unlinkat = 35,
        unshare = 97,
        userfaultfd = 282,
        utimensat = 88,
        vhangup = 58,
        vmsplice = 75,
        wait4 = 260,
        waitid = 95,
        write = 64,
        writev = 66,
    };

    /**
     * Convert general purpose register ids used in instruction encoding to arm64_reg
     * @return std::nullopt if the register id corresponds to the zero register xzr or stack pointer,
     * depending on which register id of an instruction is provided (e.g. mem accesses often don't
     * allow xzr as memory indexing register).
     */
    std::optional<arm64_reg> gp_reg_id_to_reg(uint32_t reg_id);

    bool is_load_linked(uint32_t instruction);
    bool is_store_conditional(uint32_t instruction);
    bool is_dc_zva(uint32_t instruction);

    /**
     * List transfer registers used by a load-linked store-conditional instructions.
     * Zero-registers are ignored, and not returned.
     * @param instruction LLSC instruction
     */
    std::vector<arm64_reg> get_llsc_transfer_registers(uint32_t instruction);

    /**
     * Set the transfer registers of a LD[A]X* (load exclusive) instruction, while keeping the
     * rest of the instructions operand the same
     * @param instruction Instruction to modify e.g. ldxp x14,x15,[x16]
     * @param rt Integer register encoding of the first transfer register to modify
     * @param rt2 Integer register encoding of the second transfer register to modify,
     * only used if the instruction load words from memory in two registers.
     * @return Modified instruction
     */
    uint32_t set_load_linked_transfer_registers(uint32_t instruction, uint8_t rt = 0x1f /* xzr */, uint8_t rt2 = 0x1f /* xzr */);

    /**
     * Get the status result register that stores the result of the store exclusive instruction.
     * Supports ST[L]X* instructions.
     * The register value contains 0 if the write was successful, 1 otherwise.
     * @param instruction Instruction to analyze
     * @return Status register, std::nullopt if the status doesn't get written (i.e. to zero register)
     */
    std::optional<arm64_reg> get_store_conditional_status_register(uint32_t instruction);

    /**
     * Get register containing the memory address of a load linked or store conditional memory access
     * @param instruction Instruction
     * @return Register containing the memory address
     */
    arm64_reg get_llsc_memory_access_register(uint32_t instruction);

    void print_registers(const user_pt_regs &regs);

    /**
     * Get memory reads and writes of a system call invocation
     * @param proc Process that invoked the system call
     * @param syscall_event System call and arguments
     * @return List of memory reads and writes performed by the system call
     */
    std::pair<std::vector<MemoryRegion>, std::vector<MemoryRegion>> get_syscall_memory_accesses(Process &proc, const SyscallEvent &syscall_event);
};

/**
 * A snapshot of the processor state of a particular process.
 * Registers are obtained via ptrace on-demand.
 * Its values remain valid until the process is resumed.
 */
class AArch64RegisterState {
private:
    pid_t pid_;
    std::optional<const user_pt_regs> gpregs_;    ///< General purpose registers
    std::optional<const user_fpsimd_state> simdregs_; ///< ARM Neon registers

public:
    AArch64RegisterState(pid_t pid): pid_(pid) {};
    AArch64RegisterState(pid_t pid, user_pt_regs regs): pid_(pid), gpregs_(regs) {};

    void clear();
    const user_pt_regs& get_gp_registers();
    void set_gp_registers(const user_pt_regs &regs);
    void set_syscall(int syscall_number);
    const user_fpsimd_state& get_simd_registers();
    uint64_t get_pc();
    uint64_t get_sp();
    uint64_t operator[](arm64_reg reg);
    uint64_t read_from_vex_offset(Int offset);

    /*
     * Helper functions before a system call is executed.
     * An alternative (and platform agnostic approach) would be to read from /proc/[pid]/syscall
     * which provides syscall number and arguments, but not the return value
     */
    aarch64::syscall_number get_syscall_number();
    uint64_t (&get_syscall_args())[6];
    /* Helper functions right after the syscall was executed */
    uint64_t get_syscall_retval();
};

MemoryRegion register_to_vex_region(arm64_reg reg);

/**
 * Get a list of registers that intersect with the given memory region
 */
std::vector<arm64_reg> vex_region_to_register(MemoryRegion r);

/**
 * Get register state with system call number and arguments, according to the System V ABI.
 * On AArch64, on syscall entry and exit, the x7 register is used to denote whether the ptrace
 * syscall event is of type entry or exit.
 * Reference to Linux source tree: https://elixir.bootlin.com/linux/v4.14.111/source/arch/arm64/kernel/ptrace.c#L1359
 * Modifying the register after a syscall exit event does not
 * seem to have an effect. We work around this by making sure that the x7 register has the original
 * value before and after the system call instead of setting it to 0.
 * @param regs Registers to modify
 * @param number System call number
 * @param args System call arguments
 * @return Register state that needs to be set before servicing the system call interupt
 */
void set_syscall_entry_regs(user_pt_regs &regs, uint64_t number, std::initializer_list<uint64_t> args);
