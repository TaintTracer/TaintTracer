#pragma once

#include <cstddef>
#include <debugger/Process.h>
#include <debugger/files/FileDescriptorTable.h>
#include <debugger/binder/services/BinderService.h>
#include "Parcel.h"

class FileDescriptorTable;

class BinderDriver : public OpenFileDescriptor {
public:
    BinderDriver();
    void on_syscall_exit(Process &proc, FileDescriptorTable &table, SyscallEvent &syscall_event) override;
    void bind_service_handle(uint32_t handle, std::unique_ptr<BinderService> service);

private:
    /**
     * Maps binder handles to type of object instance
     * TODO: If any service needs to persist state, use global map of global services instead of
     * unique_ptr.
     */
    std::map<uint32_t, std::unique_ptr<BinderService>> active_objects;

    /**
     * Clear binder mapping for received binder handles
     */
    void clear_replaced_services(const BinderTransaction &tx);

};

struct BinderTransaction {
    binder_transaction_data header;
    TraceeMemory tx_data_mem;
    uint64_t tx_data_size;
    TraceeMemory tx_offset_mem;
    uint64_t tx_offset_size;
    Parcel parcel;
    static BinderTransaction from_binder_tx_ptr(Process &proc, uint64_t binder_tx_ptr);
};

std::string to_string(binder_driver_command_protocol cmd);
std::string to_string(binder_driver_return_protocol cmd);

size_t payload_size(binder_driver_command_protocol cmd);
size_t payload_size(binder_driver_return_protocol cmd);

void print_binder_tx_offsets(const BinderTransaction &tx);