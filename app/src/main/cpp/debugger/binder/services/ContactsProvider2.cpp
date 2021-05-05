#include "ContactsProvider2.h"

#include <android/logging.h>
#include <debugger/binder/services/BinderService.h>
#include <debugger/binder/BinderDriver.h>

const TaintSource ContactsProvider2::source = TaintSource("ContactsProvider2::query()");

std::unique_ptr<BinderTransactionCtx>
ContactsProvider2::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                              FileDescriptorTable &fdtable) {
    auto interface = tx.parcel.read_rpc_header();
    if (interface != "android.content.IContentProvider") {
        throw std::runtime_error("Interface name mismatch");
    }
    if (tx.header.code == 1) {
        /**
         *  public Cursor query(String callingPkg, Uri url, @Nullable String[] projection,
         *      @Nullable Bundle queryArgs, @Nullable ICancellationSignal cancellationSignal)
         *      throws RemoteException;
         * https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/core/java/android/content/IContentProvider.java;l=40
         */
        auto ctx = std::make_unique<ContactProviderQueryCtx>(*this);
        ctx->on_request(tx, driver, proc, fdtable);
        return ctx;
    } else if (tx.header.code == 23) {
        /**
         *  public AssetFileDescriptor openTypedAssetFile(String callingPkg,
         *      @Nullable String attributionTag, Uri url, String mimeType, Bundle opts,
         *      ICancellationSignal signal)
         *      throws RemoteException, FileNotFoundException;
         * https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/core/java/android/content/IContentProvider.java;l=95
         */
        auto ctx = std::make_unique<ContactsProviderOpenTypedAssetFileTransactionCtx>(*this);
        ctx->on_request(tx, driver, proc, fdtable);
        return ctx;
    }
    return std::unique_ptr<BinderTransactionCtx>();
}

ContactProviderQueryCtx::ContactProviderQueryCtx(BinderService &service) : BinderTransactionCtx(
        service) {}

void ContactProviderQueryCtx::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                         FileDescriptorTable &fdtable) {

}

void ContactProviderQueryCtx::on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                       FileDescriptorTable &fdtable) {
    tx.parcel.seek_object(1);
    auto ashmem = tx.parcel.read_binder_object();
    if (ashmem->hdr.type != BINDER_TYPE_FD) {
        throw std::runtime_error("Incorrect binder object type for query(): expected file descriptor");
    }
    LOGE("Found contacts ashmem fd: %d", ashmem->handle);
    fdtable.add_fd(ashmem->handle, std::make_shared<SelectiveCursorWindowTaintFileDescriptor>(ContactsProvider2::source, "598858"));
}

ContactsProviderOpenTypedAssetFileTransactionCtx::ContactsProviderOpenTypedAssetFileTransactionCtx(
        BinderService &service) : BinderTransactionCtx(service) {}

void ContactsProviderOpenTypedAssetFileTransactionCtx::on_request(BinderTransaction &tx,
                                                                  BinderDriver &driver,
                                                                  Process &proc,
                                                                  FileDescriptorTable &fdtable) {
}

void ContactsProviderOpenTypedAssetFileTransactionCtx::on_reply(BinderTransaction &tx,
                                                                BinderDriver &driver, Process &proc,
                                                                FileDescriptorTable &fdtable) {
    tx.parcel.seek_object(0);
    auto file = tx.parcel.read_binder_object();
    if (file->hdr.type != BINDER_TYPE_FD) {
        throw std::runtime_error("Incorrect binder object type for query(): expected file descriptor");
    }
    LOGE("Found contacts asset fd: %d", file->handle);
    fdtable.add_fd(file->handle, std::make_shared<SelectiveCursorWindowTaintFileDescriptor>(ContactsProvider2::source, "598-858"));
}
