#pragma once

#include "BinderService.h"
#include <string>

enum class ContentProviderInstance {
    Unknown = 0,
    ContactsContentProvider
};

class GetContentProviderCtx : public BinderTransactionCtx {
public:
    ContentProviderInstance provider;

    GetContentProviderCtx(BinderService &service);

    void
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;

    void
    on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
             FileDescriptorTable &fdtable) override;

    ~GetContentProviderCtx() override = default;
};

class ActivityManagerService : public BinderService {
public:
    std::unique_ptr<BinderTransactionCtx>
    on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
               FileDescriptorTable &fdtable) override;
};
