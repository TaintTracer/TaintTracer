#include "FileDescriptorTable.h"

#include <android/logging.h>
#include <debugger/binder/BinderDriver.h>
#include <ghc/filesystem.hpp>
#include <fmt/format.h>
#include <magic_enum.hpp>
#include <sys/mman.h>
#include <debugger/memory/VirtualAddressSpace.h>
#include <debugger/taint/execution/InstructionUnit.h>
#include <debugger/binder/services/ContactsProvider2.h>
#include <fcntl.h>
#include <debugger/Debugger.h>

namespace fs = ghc::filesystem;

CompleteTaintFileDescriptor::CompleteTaintFileDescriptor(const TaintSource &taint_source) : taint_source_(taint_source) {}

void CompleteTaintFileDescriptor::on_syscall_exit(Process &p, FileDescriptorTable &table,
                                                  SyscallEvent &syscall) {
    if (syscall.syscall_number == aarch64::syscall_number::mmap) {
        auto &args = syscall.args;
        auto start_addr = *syscall.retval;
        auto len = (size_t) args[1];
        auto prot = (int) args[2];
        auto flags = (int) args[3];
        auto fd = (int) args[4];
        auto offset = (size_t) args[5];

        if (offset % PAGE_SIZE != 0) {
            throw std::runtime_error(fmt::format("Mapped file at a non-page-aligned offset {:#x}", offset));
        }

        auto tainted_vaddr = MemoryRegion::from_start_and_size(start_addr, len);
        LOGD("Marking memory region of CompleteTaintFileDescriptor as tainted: %s", tainted_vaddr.str().c_str());
        Debugger::at_least_one_taint_event = true;
        // TODO: Refactor taint source as field, initialized in constructor
        p.get_address_space().set_memory_taint(
                TaintEvent(ContactsProvider2::source, std::make_shared<InstructionUnit>(p)),
                tainted_vaddr);
    }
}

void SelectiveCursorWindowTaintFileDescriptor::on_syscall_exit(Process &p, FileDescriptorTable &table,
                                                               SyscallEvent &syscall) {
    auto taint_matches = [&] (MemoryRegion vm_region) -> int {
        auto mem = p.read_memory(vm_region.start_address, vm_region.size());
        const unsigned char *start = mem.data();
        const unsigned char *end = start + mem.size();
        android_hexdump(start, mem.size(), vm_region.start_address);
        unsigned int match_count = 0;
        while (start < end) {
            const unsigned char *mem_match = std::search(start, end, search_string_.begin(), search_string_.end());
            if (mem_match == end) {
                break;
            }
            auto tainted_vaddr = MemoryRegion::from_start_and_size(vm_region.start_address + (mem_match - start), search_string_.size());
            LOGD("Marking memory region of SelectiveCursorWindowTaintFileDescriptor as tainted: %s", tainted_vaddr.str().c_str());
            p.get_address_space().set_memory_taint(
                    TaintEvent(taint_source_, std::make_shared<InstructionUnit>(p)),
                    tainted_vaddr
                    );

            match_count++;
            start = mem_match + search_string_.size();
        }

        if (match_count == 0) {
            LOGW("Ignoring taint marking of mapped SelectiveCursorWindowTaintFileDescriptor: string '%s' not found in mapped memory contents", search_string_.c_str());
        }
        return match_count;
    };
    if (syscall.syscall_number == aarch64::syscall_number::mmap) {
        auto &args = syscall.args;
        auto start_addr = *syscall.retval;
        auto len = (size_t) args[1];
        auto prot = (int) args[2];
        auto flags = (int) args[3];
        auto fd = (int) args[4];
        auto offset = (size_t) args[5];

        if (offset % PAGE_SIZE != 0) {
            throw std::runtime_error(fmt::format("Mapped file at a non-page-aligned offset {:#x}", offset));
        }

        // TODO: Memory mapped length is much larger than actual payload. Get actual length from
        //       CursorWindow class. Using 0x1000 as length to search for.
        taint_matches(MemoryRegion::from_start_and_size(start_addr, 0x1000));
    } else if (syscall.syscall_number == aarch64::syscall_number::read) {
        auto [reads, writes] = aarch64::get_syscall_memory_accesses(p, syscall);
        assert(reads.empty());
        for (const auto &r : writes) {
            taint_matches(r);
        }
    }
}

SelectiveCursorWindowTaintFileDescriptor::SelectiveCursorWindowTaintFileDescriptor(const TaintSource &taint_source, std::string search_string)
    : taint_source_(taint_source), search_string_(std::move(search_string)) {}

void FileDescriptorTable::add_fd(int fd, std::shared_ptr<OpenFileDescriptor> ofd) {
    auto [it, inserted] = open_fds_.emplace(fd, std::move(ofd));
    if (!inserted) {
        throw std::runtime_error(fmt::format("Failed to import file descriptor table: already tracking fd {}", fd));
    }
}

void FileDescriptorTable::import_fds_from_procfs(pid_t pid) {
    size_t n_binder_file_handles = 0; // Number of open file handles to binder

    auto binder_dev = fs::path("/dev/binder");
    auto procfs_fds = fs::path(fmt::format("/proc/{}/fd", pid));
    for (const auto &entry : fs::directory_iterator(procfs_fds)) {
        int fd = std::stoi(entry.path().filename());
        if (fs::read_symlink(entry.path()) == binder_dev) {
            n_binder_file_handles++;
            add_fd(fd, std::make_shared<BinderDriver>());
        }
    }

    // We expect the binder driver to be already opened when we get control over the target process
    if (n_binder_file_handles != 1) {
        throw std::runtime_error(fmt::format("Expected 1 open binder file handle, got {} instead", n_binder_file_handles));
    }
}

void FileDescriptorTable::close_fd(int fd) {
    auto fd_iter = open_fds_.find(fd);
    if (fd_iter == open_fds_.end()) {
        throw std::runtime_error(fmt::format("Unable to close a file descriptor {} that wasn't found in the fd table", fd));
    }
    open_fds_.erase(fd_iter);
}

void FileDescriptorTable::on_syscall_exit(Process &p, SyscallEvent &syscall) {
    int fd;
    if (auto fd_opt = get_fd(syscall)) {
        fd = *fd_opt;
    } else {
        return; // No file descriptor referenced by the system call
    }
    auto fd_iter = open_fds_.find(fd);
    if (fd_iter == open_fds_.end()) {
        LOGW("%s", fmt::format("File descriptor {} is not tracked. Not handling syscall that references this fd: {}", fd, magic_enum::enum_name(syscall.syscall_number)).c_str());
        return;
    }
    if (syscall.syscall_number == aarch64::syscall_number::close) {
        close_fd(fd);
    } else if (syscall.syscall_number == aarch64::syscall_number::dup
               || syscall.syscall_number == aarch64::syscall_number::dup3
               || (syscall.syscall_number == aarch64::syscall_number::fcntl && (syscall.args[1] /*cmd*/ == F_DUPFD || syscall.args[1] == F_DUPFD_CLOEXEC))) {
        int duped_fd = static_cast<int>(*syscall.retval);
        auto [it, inserted] = open_fds_.emplace(duped_fd, fd_iter->second); // Copy shared pointer
        if (!inserted) {
            // TODO: Emulate close() for dup3 if newfd is already opened
            throw std::runtime_error(fmt::format("Failed to handle dup(): already tracking duplicated fd {}", duped_fd));
        }
        LOGD("File descriptor duplicated: %d -> %d", fd, duped_fd);
    }

    LOGD("Notifying tracked fd %d about syscall", fd);
    fd_iter->second->on_syscall_exit(p, *this, syscall);
}

bool FileDescriptorTable::is_binder_fd(int fd) {
    auto it = open_fds_.find(fd);
    return it != open_fds_.end() && dynamic_cast<BinderDriver *>(it->second.get());
}

bool syscall_could_reference_fd(aarch64::syscall_number syscall_number) {
    switch (syscall_number) {
        case aarch64::syscall_number::fsetxattr:
        case aarch64::syscall_number::fgetxattr:
        case aarch64::syscall_number::llistxattr:
        case aarch64::syscall_number::fremovexattr:
        case aarch64::syscall_number::epoll_ctl:
        case aarch64::syscall_number::epoll_pwait:
        case aarch64::syscall_number::dup:
        case aarch64::syscall_number::dup3:
        case aarch64::syscall_number::mknodat:
        case aarch64::syscall_number::mkdirat:
        case aarch64::syscall_number::unlinkat:
        case aarch64::syscall_number::linkat:
        case aarch64::syscall_number::renameat:
        case aarch64::syscall_number::fcntl:
        case aarch64::syscall_number::inotify_add_watch:
        case aarch64::syscall_number::inotify_rm_watch:
        case aarch64::syscall_number::ioctl:
        case aarch64::syscall_number::flock:
        case aarch64::syscall_number::fstatfs:
        case aarch64::syscall_number::ftruncate:
        case aarch64::syscall_number::fallocate:
        case aarch64::syscall_number::faccessat:
        case aarch64::syscall_number::fchdir:
        case aarch64::syscall_number::fchmod:
        case aarch64::syscall_number::fchmodat:
        case aarch64::syscall_number::fchownat:
        case aarch64::syscall_number::fchown:
        case aarch64::syscall_number::close:
        case aarch64::syscall_number::getdents64:
        case aarch64::syscall_number::lseek:
        case aarch64::syscall_number::read:
        case aarch64::syscall_number::write:
        case aarch64::syscall_number::readv:
        case aarch64::syscall_number::writev:
        case aarch64::syscall_number::pread64:
        case aarch64::syscall_number::pwrite64:
        case aarch64::syscall_number::preadv:
        case aarch64::syscall_number::pwritev:
        case aarch64::syscall_number::vmsplice:
        case aarch64::syscall_number::splice:
        case aarch64::syscall_number::tee:
        case aarch64::syscall_number::readlinkat:
        case aarch64::syscall_number::newfstatat:
        case aarch64::syscall_number::fstat:
        case aarch64::syscall_number::fsync:
        case aarch64::syscall_number::fdatasync:
        case aarch64::syscall_number::sync_file_range:
        case aarch64::syscall_number::timerfd_settime:
        case aarch64::syscall_number::timerfd_gettime:
        case aarch64::syscall_number::bind:
        case aarch64::syscall_number::listen:
        case aarch64::syscall_number::accept:
        case aarch64::syscall_number::connect:
        case aarch64::syscall_number::getsockname:
        case aarch64::syscall_number::getpeername:
        case aarch64::syscall_number::sendto:
        case aarch64::syscall_number::recvfrom:
        case aarch64::syscall_number::setsockopt:
        case aarch64::syscall_number::getsockopt:
        case aarch64::syscall_number::shutdown:
        case aarch64::syscall_number::sendmsg:
        case aarch64::syscall_number::recvmsg:
        case aarch64::syscall_number::readahead:
        case aarch64::syscall_number::mmap:
        case aarch64::syscall_number::fadvise64:
        case aarch64::syscall_number::utimensat:
        case aarch64::syscall_number::accept4:
        case aarch64::syscall_number::recvmmsg:
        case aarch64::syscall_number::fanotify_mark:
        case aarch64::syscall_number::name_to_handle_at:
        case aarch64::syscall_number::open_by_handle_at:
        case aarch64::syscall_number::syncfs:
        case aarch64::syscall_number::setns:
        case aarch64::syscall_number::sendmmsg:
        case aarch64::syscall_number::finit_module:
        case aarch64::syscall_number::renameat2:
        case aarch64::syscall_number::copy_file_range:
        case aarch64::syscall_number::preadv2:
        case aarch64::syscall_number::pwritev2:
        case aarch64::syscall_number::statx:
            return true;
        default:
            return false;
    }
}

std::optional<int> get_fd(const SyscallEvent &syscall) {
    if (!syscall_could_reference_fd(syscall.syscall_number)) {
        throw std::runtime_error("Can't obtain file descriptor for a non-fd syscall");
    }
    switch (syscall.syscall_number) {
        case aarch64::syscall_number::mmap:
        {
            auto fd = static_cast<int>(syscall.args[4]);
            auto flags = (int) syscall.args[3];
            if (flags & MAP_ANON || flags & MAP_ANONYMOUS) {
                if (fd != -1) {
                    LOGW("mmap(): called with flag MAP_ANONYMOUS but provided fd that isn't -1");
                }
                return {};
            } else {
                return fd;
            }
        }
        default:
            return static_cast<int>(syscall.args[0]);
    }
}
