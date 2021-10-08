#include "Syscall.h"
#include <debugger/Process.h>
#include <sys/uio.h>

int syscall_errno(uint64_t syscall_retval) {
    /* Map [-4095, -1] to a positive errno */
    if (-4095 <= (long long) syscall_retval && (long long) syscall_retval < 0) {
        return (int)(-(long long) syscall_retval);
    }
    return 0;
}

std::vector<MemoryRegion> get_iovec_ranges(Process &p, uint64_t iovec_vaddr, int iovec_count) {
    assert(iovec_count > 0);
    auto res = std::vector<MemoryRegion> {};
    for (size_t i = 0; i < iovec_count; i++) {
        auto iov_mem = p.read_memory(iovec_vaddr + i * sizeof(struct iovec), sizeof(struct iovec));
        auto iov_struct = (struct iovec *)iov_mem.data();
        res.emplace_back(MemoryRegion::from_start_and_size((uint64_t)iov_struct->iov_base, iov_struct->iov_len));
    }
    return res;
}
