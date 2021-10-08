#pragma once

#include <debugger/taint/source/TaintSource.h>
#include "BinderService.h"

class LocationManager : public BinderService {
public:
    static const TaintSource source;
    ~LocationManager() override = default;
    std::unique_ptr<BinderTransactionCtx>
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;
};

class RequestLocationUpdatesCtx : public BinderTransactionCtx {
public:
    RequestLocationUpdatesCtx (BinderService &service);
    ~RequestLocationUpdatesCtx() override = default;
    void on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                    FileDescriptorTable &fdtable) override;

    void on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                  FileDescriptorTable &fdtable) override;
};

class GetLastLocationCtx : public BinderTransactionCtx {
public:
    GetLastLocationCtx(BinderService &service);
    ~GetLastLocationCtx() override = default;
    void on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                    FileDescriptorTable &fdtable) override;

    void on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                  FileDescriptorTable &fdtable) override;
};

class LocationListener : public BinderService {
public:
    ~LocationListener() override = default;
    std::unique_ptr<BinderTransactionCtx>
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;

    void on_rx(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;
};
