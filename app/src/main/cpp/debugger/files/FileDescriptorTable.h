#pragma once

#include <debugger/taint/AnnotatedAddressSpace.h>
#include <debugger/Process.h>

enum class FileType {
    UNKNOWN,
    BINDER_DEVICE,
    BINDER_OBJECT,
    ASHMEM
};

struct OpenFileDescriptor {
    virtual ~OpenFileDescriptor() = default;
    virtual std::vector<MemoryRegion> get_tainted_regions() { return {}; };
    virtual void on_syscall_exit(Process &p, FileDescriptorTable &table, SyscallEvent &syscall) = 0;
};


/**
 * File descriptor whose entire content is considered to be tainted
 */
struct CompleteTaintFileDescriptor : public OpenFileDescriptor {
private:
    const TaintSource &taint_source_;
public:
    CompleteTaintFileDescriptor(const TaintSource &taint_source);
    virtual ~CompleteTaintFileDescriptor() = default;

    std::vector<MemoryRegion> get_tainted_regions() override {
        return { MemoryRegion::domain() };
    }

    void on_syscall_exit(Process &p, FileDescriptorTable &table, SyscallEvent &syscall) override;
};

/**
 * File descriptor for which we only consider the region that matches the provided string as tainted
 */
class SelectiveCursorWindowTaintFileDescriptor : public OpenFileDescriptor {
private:
    const TaintSource &taint_source_;
    std::string search_string_;
public:
    SelectiveCursorWindowTaintFileDescriptor(const TaintSource &taint_source, std::string search_string);
    virtual ~SelectiveCursorWindowTaintFileDescriptor() = default;
    void on_syscall_exit(Process &p, FileDescriptorTable &table, SyscallEvent &syscall) override;
};

/**
 * Tracks open files of a particular process
 */
class FileDescriptorTable {
public:
    FileDescriptorTable() = default;

    /**
     * Copy opened file descriptors.
     * Mirrors the effect of calling `clone()` without setting the `CLONE_FILES` flag
     */
    FileDescriptorTable(FileDescriptorTable&) = default;

    /**
     * Add a file descriptor to the table
     * @param fd Open file descriptor number
     * @param ofd Tracking instance to associate with the given file descriptor number
     */
    void add_fd(int fd, std::shared_ptr<OpenFileDescriptor> ofd);

    /**
     * Import file descriptor maps from procfs
     * @param pid Process id to query
     */
    void import_fds_from_procfs(pid_t pid);

    /**
     * Close an open file descriptor
     * @param fd Open file descriptor number
     */
    void close_fd(int fd);

    /**
     * Handle system calls that operate on an open file handle.
     * System calls that accept a path to a file are *not* handled.
     * @param p Interrupted process that initiated the system call
     * @param syscall System call to handle
     */
    void on_syscall_exit(Process &p, SyscallEvent &syscall);

    bool is_binder_fd(int fd);

private:
    std::map<int, std::shared_ptr<OpenFileDescriptor>> open_fds_;
};

/**
 * Whether the system call accept a file descriptor number as one of its arguments
 */
bool syscall_could_reference_fd(aarch64::syscall_number syscall_number);

/**
 * Get the referenced file descriptor from a syscall
 * @return File descriptor number if the system call interprets one of its arguments as a file
 * descriptor
 */
std::optional<int> get_fd(const SyscallEvent &syscall);