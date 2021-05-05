#include "ActivityManagerService.h"
#include <debugger/binder/Parcel.h>
#include <debugger/binder/BinderDriver.h>
#include "ContactsProvider2.h"
#include <fmt/format.h>
#include <android/logging.h>
#include <string>
#include <locale>
#include <codecvt>

std::unique_ptr<BinderTransactionCtx> ActivityManagerService::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                                                         FileDescriptorTable &fdtable) {
    auto interface = tx.parcel.read_rpc_header();
    if (interface != "android.app.IActivityManager") {
        throw std::runtime_error("Interface name mismatch");
    }
    LOGD("Interface invoked: %s", interface.c_str());
    if (tx.header.code == 20) {
        /*
         * ContentProviderHolder getContentProvider(in IApplicationThread caller, in String callingPackage,
         *         in String name, int userId, boolean stable);
         * https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/core/java/android/app/IActivityManager.aidl;l=137
         */
        auto ctx = std::make_unique<GetContentProviderCtx>(*this);
        ctx->on_request(tx, driver, proc, fdtable);
        return ctx;
    }
    return {};
}

void GetContentProviderCtx::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                       FileDescriptorTable &fdtable) {
    /* Read parcel */
    auto &parcel = tx.parcel;
    auto caller = parcel.read_binder_object();
    LOGD("Binder ptr: %" PRIx64, caller->binder);
    LOGD("New offset after binder obj: %zx", parcel.get_offset());
    auto calling_package = parcel.read_string_16_to_8();
    LOGD("Calling package: %s", calling_package.c_str());
    auto name = parcel.read_string_16_to_8();
    LOGD("Name: %s", name.c_str());
    int user_id = *parcel.read_int_32();
    LOGD("User ID: %d", user_id);
    bool stable = *parcel.read_int_32() != 0;
    LOGD("Stable: %s", stable ? "true" : "false");

    /* Track service requests of interest  */
    if (name == "com.android.contacts") {
        this->provider = ContentProviderInstance::ContactsContentProvider;
    }
}

void GetContentProviderCtx::on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                     FileDescriptorTable &fdtable) {
    if (tx.parcel.objects_count() == 0) {
        LOGW("Content provider was not provided in reply of getContentProvider(). Does the app have permission to obtain a handle to the content provider?");
        return;
    }
    if (provider == ContentProviderInstance::ContactsContentProvider) {
        tx.parcel.seek_object(0);
        auto contact_provider = tx.parcel.read_binder_object();
        if (contact_provider->hdr.type != BINDER_TYPE_HANDLE) {
            throw std::runtime_error("Incorrect binder object type for getContentProvider(): expected handle");
        }
        driver.bind_service_handle(contact_provider->handle, std::make_unique<ContactsProvider2>());
    }
}

GetContentProviderCtx::GetContentProviderCtx(BinderService &service) : BinderTransactionCtx(
        service) {}
