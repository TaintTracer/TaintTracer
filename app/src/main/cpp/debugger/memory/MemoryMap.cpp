#include "MemoryMap.h"
#include "PhysicalMemory.h"

MemoryMap::MemoryMap(VirtualAddressSpace *vspace, uint64_t vm_start, uint64_t vm_end,
                     bool is_shared, int prot)
        : vspace_(vspace)
        , vm_start_(vm_start)
        , vm_end_(vm_end)
        , is_shared_(is_shared)
        , prot_(prot)
        , phy_(std::make_shared<PhysicalMemory>(this))
        , phy_offset_(0) {}

MemoryMap::MemoryMap(VirtualAddressSpace *vspace, uint64_t vm_start, uint64_t vm_end,
                     bool is_shared, int prot, std::shared_ptr<PhysicalMemory> phy, uint64_t phy_offset)
        : vspace_(vspace)
        , vm_start_(vm_start)
        , vm_end_(vm_end)
        , is_shared_(is_shared)
        , prot_(prot)
        , phy_(std::move(phy))
        , phy_offset_(phy_offset) {
    phy_->add_map(this);
}

MemoryMap::MemoryMap(VirtualAddressSpace *vspace, const MemoryMap &other)
    : vspace_(vspace)
    , vm_start_(other.vm_start_)
    , vm_end_(other.vm_end_)
    , is_shared_(other.is_shared_)
    , prot_(other.prot_)
    , phy_offset_(other.phy_offset_) {
    if (other.is_shared_) {
        phy_ = other.phy_; // Share the underlying physical memory
    } else {
        phy_ = std::make_shared<PhysicalMemory>(this, *other.phy_); // Deep copy
    }
}

MemoryMap::~MemoryMap() {
    phy_->remove_map(this);
}

PhysicalMemory &MemoryMap::get_physical_memory() {
    return *phy_;
}

void MemoryMap::set_protection_flag(int prot) {
    prot_ = prot;
}

MemoryRegion MemoryMap::phy_to_virtual(MemoryRegion phy_region) const {
    if (phy_region.start_address < phy_offset_ || phy_offset_ + (vm_end_ - vm_start_) < phy_region.end_address) {
        throw std::runtime_error("Conversion from physical to virtual range failed: requested range lies outside mapped region");
    }
    return phy_region.add_offset(vm_start_ - phy_offset_);
}

MemoryRegion MemoryMap::virtual_to_phy(MemoryRegion v_region) const {
    if (v_region.start_address < vm_start_ || vm_end_ < v_region.end_address) {
        throw std::runtime_error("Conversion from virtual to physical range failed: requested range lies outside mapped region");
    }
    return v_region.add_offset(- vm_start_ + phy_offset_);
}
