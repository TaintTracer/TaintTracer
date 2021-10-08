#include "LocationManager.h"

#include <android/logging.h>
#include <debugger/binder/services/BinderService.h>
#include <debugger/binder/BinderDriver.h>
#include <debugger/taint/execution/InstructionUnit.h>

const TaintSource LocationManager::source = TaintSource("location data");

std::unique_ptr<BinderTransactionCtx>
LocationManager::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                            FileDescriptorTable &fdtable) {
    auto interface = tx.parcel.read_rpc_header();
    if (interface != "android.location.ILocationManager") {
        throw std::runtime_error("Interface name mismatch");
    }
    switch (tx.header.code) {
        case 1:
        {
            /**
             * void requestLocationUpdates(in LocationRequest request, in ILocationListener listener,
             *                             in PendingIntent intent, String packageName);
             * https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/location/java/android/location/ILocationManager.aidl;drc=114922a8fa74ecd2784d8b1b1880d3ff16f5b783;l=44
             */
            auto ctx = std::make_unique<RequestLocationUpdatesCtx>(*this);
            ctx->on_request(tx, driver, proc, fdtable);
            return ctx;
        }
        case 5:
        {
            /**
             * Location getLastLocation(in LocationRequest request, String packageName);
             * https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/location/java/android/location/ILocationManager.aidl;drc=114922a8fa74ecd2784d8b1b1880d3ff16f5b783;l=52
             */
            auto ctx = std::make_unique<GetLastLocationCtx>(*this);
            ctx->on_request(tx, driver, proc, fdtable);
            return ctx;
        }
        default:
            LOGD("Unhandled invocation of ILocationManager with code %d", tx.header.code);
    }
    return std::unique_ptr<BinderTransactionCtx>();
}

GetLastLocationCtx::GetLastLocationCtx(BinderService &service) : BinderTransactionCtx(service) {}

void GetLastLocationCtx::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                    FileDescriptorTable &fdtable) {}

void GetLastLocationCtx::on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                  FileDescriptorTable &fdtable) {
    // Parcel structure defined in https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/location/java/android/location/Location.java;drc=433bb8454515dbc55c82171a34f504ccf3d05bfe;l=1174
    auto &parcel = tx.parcel;
    if (*parcel.read_int_32() != 0 || *parcel.read_int_32() != 1) {
        LOGD("getLastLocation() reply does not contain a Location object. Service possibly returned null");
        return;
    }
    auto provider = parcel.read_string_16_to_8();
    auto time = parcel.read_int_64();
    auto elapsed_realtime_nanos = parcel.read_int_64();
    auto elapsed_realtime_uncertainty_nanos = parcel.read_int_64();
    auto fields_mask = parcel.read_int_32();
    auto tainted_region = MemoryRegion::from_start_and_size(parcel.get_tracee_ptr() + parcel.get_offset(), 2 * sizeof(double));
    auto latitude = parcel.read_double();
    auto longitude = parcel.read_double();
    auto altitude = parcel.read_double();
    LOGD("getLastLocation() reply: %f lat, %f long, %s provider", *latitude, *longitude, provider.c_str());
    /*
    parcel.writeFloat(mSpeed);
    parcel.writeFloat(mBearing);
    parcel.writeFloat(mHorizontalAccuracyMeters);
    parcel.writeFloat(mVerticalAccuracyMeters);
    parcel.writeFloat(mSpeedAccuracyMetersPerSecond);
    parcel.writeFloat(mBearingAccuracyDegrees);
    parcel.writeBundle(mExtras);
    */

    LOGD("Marking memory region with location data as tainted: %s", tainted_region.str().c_str());
    proc.get_address_space().set_memory_taint(
            TaintEvent(LocationManager::source, std::make_shared<InstructionUnit>(proc)),
            tainted_region
    );
}


RequestLocationUpdatesCtx::RequestLocationUpdatesCtx(BinderService &service) : BinderTransactionCtx(
        service) {}


void
RequestLocationUpdatesCtx::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                      FileDescriptorTable &fdtable) {
    auto &parcel = tx.parcel;
    parcel.seek_object(0);
    auto obj = parcel.read_binder_object();
    if (obj->hdr.type != BINDER_TYPE_BINDER) {
        throw std::runtime_error("Incorrect binder object type for requestLocationUpdates(): expected object type of binder");
    }
    auto callback_target = obj->handle;
    driver.bind_service_handle(callback_target, std::make_unique<LocationListener>());
}

void RequestLocationUpdatesCtx::on_reply(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                                         FileDescriptorTable &fdtable) {}

std::unique_ptr<BinderTransactionCtx>
LocationListener::on_request(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                             FileDescriptorTable &fdtable) {
    return std::unique_ptr<BinderTransactionCtx>();
}

void LocationListener::on_rx(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                             FileDescriptorTable &fdtable) {
    auto &parcel = tx.parcel;
    auto interface = tx.parcel.read_rpc_header();
    if (interface != "android.location.ILocationListener") {
        throw std::runtime_error("Interface name mismatch");
    }
    switch (tx.header.code) {
        case 1:
        {
            /**
             * void onLocationChanged(in Location location);
             * https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/base/location/java/android/location/ILocationListener.aidl;drc=da6e570f1e1a8c51d1c549dcf1a5b8907cd506bd;l=29
             */
            if (*parcel.read_int_32() != 1) {
                LOGD("onLocationChanged() callback does not contain a Location object. Service possibly returned null");
                return;
            }
            auto provider = parcel.read_string_16_to_8();
            auto time = parcel.read_int_64();
            auto elapsed_realtime_nanos = parcel.read_int_64();
            auto elapsed_realtime_uncertainty_nanos = parcel.read_int_64();
            auto fields_mask = parcel.read_int_32();
            auto tainted_region = MemoryRegion::from_start_and_size(parcel.get_tracee_ptr() + parcel.get_offset(), 2 * sizeof(double));
            auto latitude = parcel.read_double();
            auto longitude = parcel.read_double();
            auto altitude = parcel.read_double();
            LOGD("onLocationChanged() callback: %f lat, %f long, %s provider", *latitude, *longitude, provider.c_str());

            LOGD("Marking memory region with location data as tainted: %s", tainted_region.str().c_str());
            proc.get_address_space().set_memory_taint(
                    TaintEvent(LocationManager::source, std::make_shared<InstructionUnit>(proc)),
                    tainted_region
            );
            break;
        }
        default:
            LOGD("Unhandled invocation of ILocationListener with code %d", tx.header.code);
    }
}
