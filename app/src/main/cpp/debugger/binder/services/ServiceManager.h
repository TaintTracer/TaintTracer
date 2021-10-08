#pragma once

#include "BinderService.h"

class ServiceManager : public BinderService {
public:
    std::unique_ptr<BinderTransactionCtx>
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;
};

enum class ServiceManagerService {
    Unknown = 0,
    Location
};

class GetServiceCtx : public BinderTransactionCtx {
public:
    ServiceManagerService requested_service;

    GetServiceCtx(BinderService &service);

    void
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;

    void
    on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
             FileDescriptorTable &fdtable) override;

    ~GetServiceCtx() override = default;
};
