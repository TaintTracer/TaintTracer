#pragma once
#include <cstdint>
#include <debugger/taint/AnnotatedAddressSpace.h>

class Process;

/**
 * Get a libc-style error code (errno) from a system call return value
 * @param syscall_retval System call return value
 * @return Error code
 */
int syscall_errno(uint64_t syscall_retval);

/**
 * Get a list of memory regions referenced by a list of iovec structures
 * @param p Process in which the virtual address of the iovec is valid
 * @param iovec_vaddr Virtual address of the iovec
 * @param iovec_count How many iovec structures to read
 * @return List of memory regions referenced by the iovec structures
 */
std::vector<MemoryRegion> get_iovec_ranges(Process &p, uint64_t iovec_vaddr, int iovec_count);