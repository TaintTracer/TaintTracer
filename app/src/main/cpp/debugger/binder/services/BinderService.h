#pragma once

#include <memory>

class BinderDriver;
class Process;
class FileDescriptorTable;
struct BinderTransaction;
class BinderService;

/**
 * State associated with a Binder request
 */
class BinderTransactionCtx {
public:
    BinderService &service;

    BinderTransactionCtx(BinderService &service);

    virtual void on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc, FileDescriptorTable &fdtable) = 0;
    virtual void on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc, FileDescriptorTable &fdtable) = 0;
    virtual ~BinderTransactionCtx() = default;
};

class BinderService {
public:
    virtual ~BinderService() = default;
    virtual std::unique_ptr<BinderTransactionCtx> on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc, FileDescriptorTable &fdtable) = 0;
    virtual void on_rx(BinderTransaction &tx, BinderDriver &driver, Process &proc, FileDescriptorTable &fdtable);
};
