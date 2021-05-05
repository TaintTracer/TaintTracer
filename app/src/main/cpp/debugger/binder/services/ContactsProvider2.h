#pragma once

#include <debugger/taint/source/TaintSource.h>
#include "BinderService.h"

class ContactProviderQueryCtx : public BinderTransactionCtx {
public:
    ContactProviderQueryCtx(BinderService &service);
    ~ContactProviderQueryCtx() override = default;
    void on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                    FileDescriptorTable &fdtable) override;

    void on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                  FileDescriptorTable &fdtable) override;
};

class ContactsProviderOpenTypedAssetFileTransactionCtx : public BinderTransactionCtx {
public:
    ContactsProviderOpenTypedAssetFileTransactionCtx(BinderService &service);
    ~ContactsProviderOpenTypedAssetFileTransactionCtx() override = default;
    void on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                    FileDescriptorTable &fdtable) override;

    void on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                  FileDescriptorTable &fdtable) override;
};

class ContactsProvider2 : public BinderService {
public:
    static const TaintSource source;
    ~ContactsProvider2() override = default;
    std::unique_ptr<BinderTransactionCtx>
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;
};
