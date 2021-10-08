#include <android/logging.h>
#include "Parcel.h"
#include <fmt/format.h>
#include <codecvt>
#include <locale>

Parcel::Parcel(const unsigned char *parcel_data, size_t data_size, const unsigned char *offsets, size_t offsets_size, uint64_t tracee_ptr)
    : parcel_data_(parcel_data), data_size_(data_size), offsets_(offsets), offsets_size_(offsets_size), offset_(0), tracee_ptr_(tracee_ptr) {}

static size_t padded(size_t size) {
    return size + ((size % 4 == 0) ? 0 : (4 - (size % 4)));
}

void Parcel::reset() {
    offset_ = 0;
}

void *Parcel::read_inplace(size_t len, bool padding) {
    auto ptr = parcel_data_ + offset_;
    offset_ += padding ? padded(len) : len;
    if (offset_ > data_size_) {
        throw std::runtime_error(fmt::format("Parcel offset out of bounds after reading {} bytes", len));
    }
    return (void *) ptr;
}

int *Parcel::read_bool() {
    return read_int_32();
}

int *Parcel::read_int_32() {
    return (int *) read_inplace(4, false);
}

long *Parcel::read_int_64() {
    return (int64_t *) read_inplace(8, false);
}

double *Parcel::read_double() {
    return (double *) read_inplace(8, false);
}

std::u16string_view Parcel::read_string_16() {
    /*
     * Derived from https://cs.android.com/android/platform/superproject/+/android10-release:system/libhwbinder/Parcel.cpp;l=90;bpv=0;bpt=1
     */
    size_t characters = static_cast<size_t>(*read_int_32());
    auto ptr = read_inplace((characters + 1) * sizeof(char16_t), true);
    // LOGE("String at offset %zu of length %zu", offset, characters);
    return std::u16string_view(reinterpret_cast<const char16_t *>(ptr), characters);
}

std::string Parcel::read_string_16_to_8() {
    auto u16 = read_string_16();
    auto converter = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {};
    return converter.to_bytes(u16.begin(), u16.end());
}

flat_binder_object *Parcel::read_binder_object() {
    auto ptr = parcel_data_ + offset_;
    auto object = (flat_binder_object *) ptr;
    // Sanity check
    // Derived from https://cs.android.com/android/platform/superproject/+/android10-release:system/libhwbinder/Parcel.cpp;l=90;bpv=0;bpt=1
    switch (object->hdr.type) {
        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER:
        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE:
        case BINDER_TYPE_FD:
            break;
        default:
            throw std::runtime_error(fmt::format("No binder object at offset {:#x} Got header type {:#x}", offset_, object->hdr.type));
    }
    offset_ += sizeof(flat_binder_object);
    return (flat_binder_object *) ptr;
}

std::string Parcel::read_rpc_header() {
    auto strict_mode = read_int_32();
    auto work_source = read_int_32();
    return read_string_16_to_8();
}

size_t Parcel::objects_count() {
    return offsets_size_ / sizeof(binder_size_t);
}

size_t Parcel::seek_object(unsigned int object_index) {
    if (object_index >= objects_count()) {
        throw std::runtime_error("Tried to seek to an out-of-bounds object");
    }
    offset_ = *(binder_size_t *) (offsets_ + object_index * sizeof(binder_size_t));
    if (offset_ + sizeof(binder_object_header) > data_size_) {
        throw std::runtime_error("Binder object offset is out-of-bounds");
    }
    return offset_;
}

size_t Parcel::get_offset() const {
    return offset_;
}

size_t Parcel::get_tracee_ptr() const {
    return tracee_ptr_;
}
