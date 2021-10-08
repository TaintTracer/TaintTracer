#include "ServiceManager.h"
#include "LocationManager.h"
#include <debugger/binder/Parcel.h>
#include <debugger/binder/BinderDriver.h>
#include <android/logging.h>

std::unique_ptr <BinderTransactionCtx>
ServiceManager::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                           FileDescriptorTable &fdtable) {
    auto interface = tx.parcel.read_rpc_header();
    if (interface != "android.os.IServiceManager") {
        throw std::runtime_error("Interface name mismatch");
    }
    LOGD("Interface invoked: %s", interface.c_str());

    if (tx.header.code == 1) {
        /*
         * IBinder getService(String name) throws RemoteException;
         * https://android.googlesource.com/platform/frameworks/base/+/android10-release/core/java/android/os/IServiceManager.java#33
         */
        auto ctx = std::make_unique<GetServiceCtx>(*this);
        ctx->on_request(tx, driver, proc, fdtable);
        return ctx;
    }
    return {};
}

GetServiceCtx::GetServiceCtx(BinderService &service) : BinderTransactionCtx(service) {}

void GetServiceCtx::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                               FileDescriptorTable &fdtable) {
    /* Read parcel */
    auto &parcel = tx.parcel;
    auto name = parcel.read_string_16_to_8();
    if (name == "location") {
        requested_service = ServiceManagerService::Location;
    }
}

void GetServiceCtx::on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                             FileDescriptorTable &fdtable) {
    if (requested_service == ServiceManagerService::Location) {
        tx.parcel.seek_object(0);
        auto contact_provider = tx.parcel.read_binder_object();
        if (contact_provider->hdr.type != BINDER_TYPE_HANDLE) {
            throw std::runtime_error("Incorrect binder object type for getContentProvider(): expected handle");
        }
        driver.bind_service_handle(contact_provider->handle, std::make_unique<LocationManager>());
    }
}
