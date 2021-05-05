#include <catch2/catch.hpp>
#include <debugger/Process.h>
#include <debugger/memory/VirtualAddressSpace.h>
#include <debugger/memory/PhysicalMemory.h>
#include <sys/mman.h>
#include <debugger/Debugger.h>

TEST_CASE("virtual address space") {
    constexpr int pid = 1;
    Debugger d{};
    SECTION("single vspace, single process") {
        auto p = Process{d, pid};
        REQUIRE(p.get_address_space().get_any_associated_process().get_pid() == pid);
        MemoryMap& map = p.get_address_space().add_memory_map(0x1000, 0x2000, false, PROT_NONE);
        REQUIRE(p.get_address_space().get_memory_map(0x1000, 0x2000) != std::nullopt);
        REQUIRE(&p.get_address_space().get_memory_map(0x1000, 0x2000)->first == &map);
        REQUIRE(p.get_address_space().get_memory_map(0x1001, 0x2000) != std::nullopt);
        REQUIRE(p.get_address_space().get_memory_map(0x1000, 0x1999) != std::nullopt);
        REQUIRE(p.get_address_space().get_memory_map(0x1001, 0x1999) != std::nullopt);
        REQUIRE(map.get_physical_memory().get_all_vaddrs(MemoryRegion(0x42, 0x43)).size() == 1);
        REQUIRE(map.get_physical_memory().get_all_vaddrs(MemoryRegion(0x42, 0x43)).begin()->second.start_address == 0x1042);
    }

    SECTION("partial unmap") {
        auto p = Process{d, pid};
        auto& map = p.get_address_space().add_memory_map(0x1000, 0x4000, false, PROT_NONE);
        REQUIRE(&p.get_address_space().get_memory_map(0x1000, 0x2000)->first == &map);

        CHECK(map.vm_start_ == 0x1000);
        CHECK(map.vm_end_ == 0x4000);
        CHECK(map.phy_offset_ == 0);

        p.get_address_space().remove_memory_map(0x1000, 0x2000);
        REQUIRE(p.get_address_space().get_memory_map(0x1000, 0x2000) == std::nullopt);
        REQUIRE(&p.get_address_space().get_memory_map(0x2000, 0x4000)->first == &map);

        CHECK(map.vm_start_ == 0x2000);
        CHECK(map.vm_end_ == 0x4000);
        CHECK(map.phy_offset_ == 0x1000);

        p.get_address_space().remove_memory_map(0x2000, 0x4000);
        REQUIRE(p.get_address_space().get_memory_map(0, 0-0x1000) == std::nullopt);
    }

    SECTION("partial unmap with copy split") {
        auto p = Process{d, pid};
        auto& map = p.get_address_space().add_memory_map(0x1000, 0x4000, false, PROT_NONE);
        REQUIRE(&p.get_address_space().get_memory_map(0x1000, 0x2000)->first == &map);

        CHECK(map.vm_start_ == 0x1000);
        CHECK(map.vm_end_ == 0x4000);
        CHECK(map.phy_offset_ == 0);

        p.get_address_space().remove_memory_map(0x2000, 0x3000);
        REQUIRE(p.get_address_space().get_memory_map(0x2000, 0x3000) == std::nullopt);
        REQUIRE(p.get_address_space().get_memory_map(0x1000, 0x2000));
        REQUIRE(p.get_address_space().get_memory_map(0x3000, 0x4000));
        auto& map1 = p.get_address_space().get_memory_map(0x1000, 0x2000)->first;
        auto& map2 = p.get_address_space().get_memory_map(0x3000, 0x4000)->first;

        CHECK(map1.vm_start_ == 0x1000);
        CHECK(map1.vm_end_ == 0x2000);
        CHECK(map1.phy_offset_ == 0);

        CHECK(map2.vm_start_ == 0x3000);
        CHECK(map2.vm_end_ == 0x4000);
        CHECK(map2.phy_offset_ == 0x2000);
    }

    SECTION("mmap in the middle of an existing memory map") {
        auto p = Process{d, pid};
        auto& map = p.get_address_space().add_memory_map(0x1000, 0x4000, false, PROT_NONE);

        p.get_address_space().add_memory_map(0x2000, 0x3000, true, PROT_WRITE);
        auto& map1 = p.get_address_space().get_memory_map(0x1000, 0x2000)->first;
        auto& map2 = p.get_address_space().get_memory_map(0x2000, 0x3000)->first;
        auto& map3 = p.get_address_space().get_memory_map(0x3000, 0x4000)->first;

        CHECK(map1.vm_start_ == 0x1000);
        CHECK(map1.vm_end_ == 0x2000);
        CHECK(map1.phy_offset_ == 0);
        CHECK(!map1.is_shared_);
        CHECK(map1.prot_ == PROT_NONE);

        CHECK(map2.vm_start_ == 0x2000);
        CHECK(map2.vm_end_ == 0x3000);
        CHECK(map2.phy_offset_ == 0);
        CHECK(map2.is_shared_);
        CHECK(map2.prot_ == PROT_WRITE);

        CHECK(map3.vm_start_ == 0x3000);
        CHECK(map3.vm_end_ == 0x4000);
        CHECK(map3.phy_offset_ == 0x2000);
        CHECK(!map3.is_shared_);
        CHECK(map3.prot_ == PROT_NONE);
    }
}
