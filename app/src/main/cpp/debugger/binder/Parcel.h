#pragma once

#include <debugger/Process.h>
class Parcel {
public:
    Parcel(const unsigned char *parcel_data, size_t data_size,
           const unsigned char *offsets, size_t offsets_size,
           uint64_t tracee_ptr);

    /**
     * Reset offset to read the next item to the beginning of the buffer
     */
    void reset();

    void *read_inplace(size_t len, bool should_pad);

    int *read_bool();

    int *read_int_32();

    long *read_int_64();

    double *read_double();

    /**
     * Reads UTF-16 strings written into the parcel by `status_t Parcel::writeString16(const char16_t* str, size_t len)`: https://cs.android.com/android/platform/superproject/+/android10-release:frameworks/native/libs/binder/Parcel.cpp;l=1116;bpv=0;bpt=1
     * @return
     */
    std::u16string_view read_string_16();

    /**
     * Read a UTF-16 encoded string and convert it to a UTF-8 encoded string
     */
    std::string read_string_16_to_8();

    flat_binder_object *read_binder_object();

    /**
     * Read RPC header
     * @return Interface name of which we invoke a remote method
     */
    std::string read_rpc_header();

    /**
     * Get number of Binder objects
     */
    size_t objects_count();

    /**
     * Seek to a Binder object
     * @param object_index Index number of Binder objects referenced by the offsets buffer
     * @return Offset of the inlined object in the Binder object buffer
     */
    size_t seek_object(unsigned int object_index);

    /**
     * Get the offset of the current seek position
     */
    size_t get_offset() const;

    /**
     * Get the tracee memory address that points to the parcel (without offset)
     */
    uint64_t get_tracee_ptr() const;

private:
    const unsigned char *parcel_data_;
    size_t data_size_;

    const unsigned char *offsets_;
    size_t offsets_size_;

    uint64_t tracee_ptr_;

    size_t offset_;
};
