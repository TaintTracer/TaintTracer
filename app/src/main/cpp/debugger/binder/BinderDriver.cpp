#include "BinderDriver.h"
#include <stdexcept>
#include <android/logging.h>
#include <inttypes.h>
#include <string>
#include <linux/android/binder.h>
#include <fmt/format.h>
#include <ghc/filesystem.hpp>
#include <debugger/binder/services/ActivityManagerService.h>
#include <debugger/binder/services/ServiceManager.h>
#include <debugger/Config.h>
#include "Parcel.h"

namespace fs = ghc::filesystem;

void print_binder_tx_offsets(const BinderTransaction& tx) {
    for (binder_size_t i = 0; i < tx.tx_offset_size; i += sizeof(binder_size_t)) {
        auto data_offset = *(binder_size_t *) (tx.tx_offset_mem.data() + i);
        if (data_offset + sizeof(binder_object_header) > tx.tx_data_size) {
            throw std::runtime_error("Binder object offset is out-of-bounds");
        }
        auto object_header = (binder_object_header *)(tx.tx_data_mem.data() + data_offset);
        LOGD("Binder object %#08x at offset 0x%" PRIx64, object_header->type, data_offset);
        switch (object_header->type) {
            case BINDER_TYPE_BINDER:
                LOGD("Binder object type: binder");
                break;
            case BINDER_TYPE_WEAK_BINDER:
                LOGD("Binder object type: weak binder");
                break;
            case BINDER_TYPE_HANDLE:
            {
                auto object = (flat_binder_object *) object_header;
                LOGD("Binder object type: handle: %d", object->handle);
                break;
            }
            case BINDER_TYPE_WEAK_HANDLE:
                LOGD("Binder object type: weak handle");
                break;
            case BINDER_TYPE_FD:
            {
                auto object = (binder_fd_object *) object_header;
                LOGD("Binder object type: file descriptor: %d", object->fd);
                break;
            }
            case BINDER_TYPE_FDA:
                LOGD("Binder object type: file descriptor array");
                break;
            case BINDER_TYPE_PTR:
                LOGD("Binder object type: pointer");
                break;
            default:
                throw std::runtime_error("Unexpected binder object type: " + std::to_string(object_header->type));
        }
    }
}

BinderTransaction
BinderTransaction::from_binder_tx_ptr(Process &proc, uint64_t binder_tx_ptr) {
    auto tx_mem = proc.read_memory(binder_tx_ptr, sizeof(binder_transaction_data));
    auto tx = (binder_transaction_data *) tx_mem.data();
    LOGD("Binder TX target: %u sender_pid: %d code: %u cookie: %llx tx_data_size: 0x%" PRIx64 " type: %s", tx->target.handle, tx->sender_pid, tx->code, tx->cookie, tx->data_size, (tx->flags & TF_ONE_WAY) ? "one-way" : "blocking");
    LOGD("Binder offset size: %llu", tx->offsets_size);
    auto tx_data_size = tx->data_size;
    auto tx_data_mem = proc.read_memory(tx->data.ptr.buffer, tx_data_size);
    auto tx_offsets_size = tx->offsets_size;
    auto tx_offsets_mem = proc.read_memory(tx->data.ptr.offsets, tx_offsets_size);
    auto parcel = Parcel(tx_data_mem.data(), tx_data_size, tx_offsets_mem.data(), tx_offsets_size, tx->data.ptr.buffer);
    return {
        .header = *tx,
        .tx_data_mem = std::move(tx_data_mem),
        .tx_data_size = tx_data_size,
        .tx_offset_mem = std::move(tx_offsets_mem),
        .tx_offset_size = tx_offsets_size,
        .parcel = std::move(parcel)
    };
}

std::string to_string(binder_driver_command_protocol cmd) {
    switch (cmd) {
        case BC_TRANSACTION:
            return "BC_TRANSACTION";
        case BC_REPLY:
            return "BC_REPLY";
        case BC_ACQUIRE_RESULT:
            return "BC_ACQUIRE_RESULT";
        case BC_FREE_BUFFER:
            return "BC_FREE_BUFFER";
        case BC_INCREFS:
            return "BC_INCREFS";
        case BC_ACQUIRE:
            return "BC_ACQUIRE";
        case BC_RELEASE:
            return "BC_RELEASE";
        case BC_DECREFS:
            return "BC_DECREFS";
        case BC_INCREFS_DONE:
            return "BC_INCREFS_DONE";
        case BC_ACQUIRE_DONE:
            return "BC_ACQUIRE_DONE";
        case BC_ATTEMPT_ACQUIRE:
            return "BC_ATTEMPT_ACQUIRE";
        case BC_REGISTER_LOOPER:
            return "BC_REGISTER_LOOPER";
        case BC_ENTER_LOOPER:
            return "BC_ENTER_LOOPER";
        case BC_EXIT_LOOPER:
            return "BC_EXIT_LOOPER";
        case BC_REQUEST_DEATH_NOTIFICATION:
            return "BC_REQUEST_DEATH_NOTIFICATION";
        case BC_CLEAR_DEATH_NOTIFICATION:
            return "BC_CLEAR_DEATH_NOTIFICATION";
        case BC_DEAD_BINDER_DONE:
            return "BC_DEAD_BINDER_DONE";
        case BC_TRANSACTION_SG:
            return "BC_TRANSACTION_SG";
        case BC_REPLY_SG:
            return "BC_REPLY_SG";
        default:
            throw std::runtime_error("Unexpected binder command: " + std::to_string(cmd));
    }
}

std::string to_string(binder_driver_return_protocol cmd) {
    switch (cmd) {
        case BR_ERROR:
            return "BR_ERROR";
        case BR_OK:
            return "BR_OK";
        case BR_TRANSACTION_SEC_CTX:
            return "BR_TRANSACTION_SEC_CTX";
        case BR_TRANSACTION:
            return "BR_TRANSACTION";
        case BR_REPLY:
            return "BR_REPLY";
        case BR_ACQUIRE_RESULT:
            return "BR_ACQUIRE_RESULT";
        case BR_DEAD_REPLY:
            return "BR_DEAD_REPLY";
        case BR_TRANSACTION_COMPLETE:
            return "BR_TRANSACTION_COMPLETE";
        case BR_INCREFS:
            return "BR_INCREFS";
        case BR_ACQUIRE:
            return "BR_ACQUIRE";
        case BR_RELEASE:
            return "BR_RELEASE";
        case BR_DECREFS:
            return "BR_DECREFS";
        case BR_ATTEMPT_ACQUIRE:
            return "BR_ATTEMPT_ACQUIRE";
        case BR_NOOP:
            return "BR_NOOP";
        case BR_SPAWN_LOOPER:
            return "BR_SPAWN_LOOPER";
        case BR_FINISHED:
            return "BR_FINISHED";
        case BR_DEAD_BINDER:
            return "BR_DEAD_BINDER";
        case BR_CLEAR_DEATH_NOTIFICATION_DONE:
            return "BR_CLEAR_DEATH_NOTIFICATION_DONE";
        case BR_FAILED_REPLY:
            return "BR_FAILED_REPLY";
        default:
            throw std::runtime_error("Unexpected binder return command: " + std::to_string(cmd));
    }
}

size_t payload_size(binder_driver_command_protocol cmd) {
    switch (cmd) {
        case BC_TRANSACTION:
        case BC_REPLY:
            return sizeof(binder_transaction_data);
        case BC_ACQUIRE_RESULT:
            return sizeof(__s32);
        case BC_FREE_BUFFER:
            return sizeof(binder_uintptr_t);
        case BC_INCREFS:
        case BC_ACQUIRE:
        case BC_RELEASE:
        case BC_DECREFS:
            return sizeof(uint32_t); // target
        case BC_INCREFS_DONE:
        case BC_ACQUIRE_DONE:
            return sizeof(binder_ptr_cookie);
        case BC_ATTEMPT_ACQUIRE:
            return sizeof(binder_pri_desc);
        case BC_REGISTER_LOOPER:
        case BC_ENTER_LOOPER:
        case BC_EXIT_LOOPER:
            return 0;
        case BC_REQUEST_DEATH_NOTIFICATION:
        case BC_CLEAR_DEATH_NOTIFICATION:
            return sizeof(binder_handle_cookie);
        case BC_DEAD_BINDER_DONE:
            return sizeof(binder_uintptr_t); // void *: cookie
        case BC_TRANSACTION_SG:
        case BC_REPLY_SG:
            return sizeof(binder_transaction_data_sg);
        default:
            throw std::runtime_error("Invalid binder command provided");
    }
}

size_t payload_size(binder_driver_return_protocol cmd) {
    switch (cmd) {
        case BR_OK:
        case BR_DEAD_REPLY:
        case BR_TRANSACTION_COMPLETE:
        case BR_NOOP:
        case BR_SPAWN_LOOPER:
        case BR_FINISHED:
        case BR_FAILED_REPLY:
            // No arguments
            return 0;
        case BR_ERROR:
        case BR_ACQUIRE_RESULT :
            return  sizeof(__s32);
        case BR_TRANSACTION_SEC_CTX:
            return sizeof(struct binder_transaction_data_secctx);
        case BR_TRANSACTION :
        case BR_REPLY :
            return sizeof(struct binder_transaction_data);
        case BR_INCREFS :
        case BR_ACQUIRE :
        case BR_RELEASE :
        case BR_DECREFS :
        case BR_ATTEMPT_ACQUIRE :
            return sizeof(struct binder_ptr_cookie);
        case BR_DEAD_BINDER :
        case BR_CLEAR_DEATH_NOTIFICATION_DONE :
            return sizeof(binder_uintptr_t);
        default:
            throw std::runtime_error("Invalid binder return command provided");
    }
}

BinderDriver::BinderDriver() {
    active_objects.emplace(0, std::make_unique<ServiceManager>());
    active_objects.emplace(1, std::make_unique<ActivityManagerService>());
}

void BinderDriver::on_syscall_exit(Process &proc, FileDescriptorTable &table, SyscallEvent &syscall_event) {
    if (syscall_event.syscall_number == aarch64::syscall_number::ioctl) {
        auto &args = syscall_event.args;
        auto binder_dev = fs::path("/dev/binder");
        int fd = (int)args[0];
        auto ioctl_fd = fs::path(fmt::format("/proc/{}/fd/{}", proc.get_pid(), fd));
        if (fs::exists(ioctl_fd)) {
            if (fs::equivalent(ioctl_fd, binder_dev)) {
                uint64_t ioctl_cmd = syscall_event.args[1];
                if (ioctl_cmd == BINDER_WRITE_READ) {
                    LOGD("ioctl() to binder with command BINDER_WRITE_READ");
                    uint64_t bwr_tracee_ptr = syscall_event.args[2];
                    if (syscall_event.bwr_pre == std::nullopt) {
                        throw std::runtime_error("binder bwr state not set on syscall entry");
                    }
                    auto bwr_pre = *syscall_event.bwr_pre;
                    // Read binder_write_read after syscall
                    auto bwr_mem = proc.read_memory(bwr_tracee_ptr, sizeof(binder_write_read));
                    struct binder_write_read *bwr = (binder_write_read *) bwr_mem.data();
                    if (bwr_pre.read_buffer != bwr->read_buffer || bwr_pre.write_buffer != bwr->write_buffer) {
                        throw std::runtime_error("Assumption violated: binder bwr read or write buffer pointer has been changed by the driver");
                    }
                    LOGD("Tracee sent payload of %llu bytes via binder", bwr->write_size);
                    LOGD("Tracee received payload of %llu bytes via binder", bwr->read_size);

                    /*
                     * Handle outgoing write buffer from the process to the target service.
                     * Read binder command similar to the kernel driver.
                     * See `binder_thread_write` at https://elixir.bootlin.com/linux/v4.14.111/source/drivers/android/binder.c#L3238
                     */
                    {
                        uint64_t ptr = bwr->write_buffer + bwr_pre.write_consumed;
                        uint64_t end = bwr->write_buffer + bwr->write_consumed;
                        while (ptr < end) {
                            auto command_mem = proc.read_memory(ptr, sizeof(uint32_t));
                            auto cmd = (const binder_driver_command_protocol) *(uint32_t*) command_mem.data();
                            ptr += sizeof(uint32_t);
                            assert (ptr <= end);
                            auto cmd_str = to_string(cmd);
                            LOGD("Binder command in write buffer: %s", cmd_str.c_str());
                            if (cmd == BC_TRANSACTION) {
                                auto tx = BinderTransaction::from_binder_tx_ptr(proc, ptr);
                                print_binder_tx_offsets(tx);
                                if (Config::print_binder_payload) {
                                    LOGD("Hexdump of sent tx data:");
                                    android_hexdump(tx.tx_data_mem.data(), tx.tx_data_size);
                                }
                                auto service_it = active_objects.find(tx.header.target.handle);
                                if (service_it != active_objects.end()) {
                                    proc.set_binder_ctx(service_it->second->on_request(tx, *this, proc, table));
                                }
                            } else if (cmd == BC_TRANSACTION_SG) {
                                throw std::runtime_error("NYI: Binder scatter-gather command");
                            }
                            // Skip past command payload
                            ptr += payload_size(cmd);
                        }
                    }
                    /*
                     * Handle incoming read buffer from the service
                     * Parsing such messages is performed by IPCThreadState in
                     * userspace. See: https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android10-release/libs/binder/IPCThreadState.cpp
                     * We assume (and assert) that the read buffer before syscall
                     * entry is completely empty.
                     */
                    {
                        uint64_t ptr = bwr->read_buffer + bwr_pre.read_consumed;
                        uint64_t end = bwr->read_buffer + bwr->read_consumed;
                        while (ptr < end) {
                            auto command_mem = proc.read_memory(ptr, sizeof(uint32_t));
                            auto cmd = (const binder_driver_return_protocol) *(uint32_t*) command_mem.data();
                            ptr += sizeof(uint32_t);
                            assert (ptr <= end);
                            // Print message type
                            auto cmd_str = to_string(cmd);
                            LOGD("Binder command in read buffer: %s", cmd_str.c_str());
                            if (cmd == BR_TRANSACTION || cmd == BR_REPLY) {
                                auto tx = BinderTransaction::from_binder_tx_ptr(proc, ptr);
                                print_binder_tx_offsets(tx);
                                if (Config::print_binder_received_data) {
                                    LOGD("Hexdump of received tx data:");
                                    android_hexdump(tx.tx_data_mem.data(), tx.tx_data_size);
                                }
                                clear_replaced_services(tx); // Clear services of reallocated handles
                                if (proc.get_binder_ctx()) {
                                    if (cmd == BR_TRANSACTION) {
                                        throw std::runtime_error("Expected BR_REPLY instead of BR_TRANSACTION");
                                    }
                                    proc.get_binder_ctx()->on_reply(tx, *this, proc, table);
                                    proc.set_binder_ctx(std::unique_ptr<BinderTransactionCtx>{});
                                } else {
                                    auto service_it = active_objects.find(tx.header.target.handle);
                                    if (service_it != active_objects.end()) {
                                        service_it->second->on_rx(tx, *this, proc, table);
                                    } else {
                                        LOGW("Received binder reply or tx, but ignoring it since the current thread has no request context");
                                    }
                                }
                                for (binder_size_t i = 0; i < tx.tx_offset_size; i += sizeof(binder_size_t)) {
                                    auto data_offset = *(binder_size_t *) (
                                            tx.tx_offset_mem.data() + i);
                                    if (data_offset + sizeof(binder_object_header) >
                                        tx.tx_data_size) {
                                        throw std::runtime_error(
                                                "Binder object offset is out-of-bounds");
                                    }
                                    auto object_header = (binder_object_header *) (
                                            tx.tx_data_mem.data() + data_offset);
                                    LOGD("Binder object %#08x at offset 0x%"
                                                 PRIx64, object_header->type,
                                         data_offset);
                                    if (object_header->type == BINDER_TYPE_FD) {
                                        auto object = (binder_fd_object *) object_header;
                                        // TODO: Mark fd as tainted
                                    }
                                }
                            }

                            // Skip past reply payload
                            ptr += payload_size(cmd);
                        }
                    }
                }
            } else {
                throw std::runtime_error("BinderDriver::on_syscall_exit called on non-binder file");
            }
        } else {
            throw std::runtime_error(fmt::format("fd {} not found in procfs of pid {}", ioctl_fd.string(), fd));
        }
    }
}

void BinderDriver::bind_service_handle(uint32_t handle, std::unique_ptr<BinderService> service) {
    /*
     * TODO: We are destructing the service if handle already maps to a service.
     * This may happen if e.g.another thread is interested in the same service.
     */
    active_objects[handle] = std::move(service);
}

void BinderDriver::clear_replaced_services(const BinderTransaction &tx) {
    for (binder_size_t i = 0; i < tx.tx_offset_size; i += sizeof(binder_size_t)) {
        auto data_offset = *(binder_size_t *) (tx.tx_offset_mem.data() + i);
        if (data_offset + sizeof(binder_object_header) > tx.tx_data_size) {
            throw std::runtime_error("Binder object offset is out-of-bounds");
        }
        auto object_header = (binder_object_header *) (tx.tx_data_mem.data() + data_offset);
        if (object_header->type == BINDER_TYPE_HANDLE) {
            auto object = (flat_binder_object *) object_header;
            auto handle = object->handle;
            auto it = active_objects.find(handle);
            if (it != active_objects.end()) {
                LOGD("Removing bound Binder service with handle %d", handle);
                active_objects.erase(it);
            }
        }
    }
}
