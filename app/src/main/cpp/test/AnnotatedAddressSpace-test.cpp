#include <catch2/catch.hpp>
#include <debugger/taint/AnnotatedAddressSpace.h>
#include <android/logging.h>
#include <unistd.h>

TEST_CASE("memory region intersection") {
    SECTION("non-overlapping") {
        REQUIRE(intersects(MemoryRegion(0,0), MemoryRegion(0,0)) == std::nullopt);
        REQUIRE(intersects(MemoryRegion(1,1), MemoryRegion(0,0)) == std::nullopt);
        REQUIRE(intersects(MemoryRegion(1,1), MemoryRegion(2,2)) == std::nullopt);
        REQUIRE(intersects(MemoryRegion(0,10), MemoryRegion(10,20)) == std::nullopt);
        REQUIRE(intersects(MemoryRegion(1,2), MemoryRegion(3,4)) == std::nullopt);
        REQUIRE(intersects(MemoryRegion(5,10), MemoryRegion(0,5)) == std::nullopt);
    }

    SECTION("single-ended overlap") {
        REQUIRE(intersects(MemoryRegion(0,10), MemoryRegion(5,15)) == MemoryRegion(5,10));
        REQUIRE(intersects(MemoryRegion(5,10), MemoryRegion(0,6)) == MemoryRegion(5,6));
    }

    SECTION("complete overlap") {
        REQUIRE(intersects(MemoryRegion(5,15), MemoryRegion(7,14)) == MemoryRegion(7,14));
        REQUIRE(intersects(MemoryRegion(5,15), MemoryRegion(5,14)) == MemoryRegion(5,14));
        REQUIRE(intersects(MemoryRegion(5,15), MemoryRegion(5,15)) == MemoryRegion(5,15));
        REQUIRE(intersects(MemoryRegion(5,15), MemoryRegion(6,15)) == MemoryRegion(6,15));
    }
}

TEST_CASE("memory region page-alignment") {
    SECTION("intersecting pages") {
        REQUIRE(MemoryRegion(0, 4096).intersecting_pages() == MemoryRegion(0, 4096));
        REQUIRE(MemoryRegion(0, 4097).intersecting_pages() == MemoryRegion(0, 4096));
        REQUIRE(MemoryRegion(0, 4095).intersecting_pages() == std::nullopt);
        REQUIRE(MemoryRegion(PAGE_SIZE + 0x42, PAGE_SIZE + 0x43).intersecting_pages() == std::nullopt);
        REQUIRE(MemoryRegion(PAGE_SIZE + 0x42, 2 * PAGE_SIZE + 0x43).intersecting_pages() == std::nullopt);
        REQUIRE(MemoryRegion(PAGE_SIZE + 0x42, 3 * PAGE_SIZE + 0x43).intersecting_pages() == MemoryRegion(2 * PAGE_SIZE, 3 * PAGE_SIZE));
    }
}

TEST_CASE("memory region merge") {
    char ccc[2048];
    auto r1 = MemoryRegion(10, 20);
    auto r2 = MemoryRegion(20, 30);
    auto r3 = MemoryRegion(30, 40);
    auto merged = MemoryRegion(10, 40);
    CHECK(merge_consecutive_regions({r1, r2, r3}) == merged);
    CHECK(merge_consecutive_regions({r1, r3, r2}) == merged);
    CHECK(merge_consecutive_regions({r2, r1, r3}) == merged);
    CHECK(merge_consecutive_regions({r2, r3, r1}) == merged);
    CHECK(merge_consecutive_regions({r3, r1, r2}) == merged);
    CHECK(merge_consecutive_regions({r3, r2, r1}) == merged);
}

TEST_CASE("annotated address space") {
    AnnotatedAddressSpace<int> s;
    REQUIRE(s.size() == 0);

    SECTION("insert a single element") {
        AnnotatedMemoryRegion<int> a(3, 5, 42);
        s.insert(a);
        REQUIRE(s.size() == 1);

        REQUIRE(s.num_intersections(MemoryRegion(0, 0)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 1)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(2, 2)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(3, 3)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(4, 4)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(5, 5)) == 0);

        REQUIRE(s.num_intersections(MemoryRegion(0, 1)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 2)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(2, 3)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(3, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(4, 5)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(5, 6)) == 0);

        REQUIRE(s.num_intersections(MemoryRegion(0, 2)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 3)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(2, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(3, 5)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(4, 6)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(5, 7)) == 0);
    }

    SECTION("insert two non-intersecting elements") {
        s = {};
        AnnotatedMemoryRegion<int> a(1, 3, 42);
        AnnotatedMemoryRegion<int> b(3, 5, 43);
        s.insert(a);
        REQUIRE(s.size() == 1);
        s.insert(b);
        REQUIRE(s.size() == 2);

        REQUIRE(s.num_intersections(MemoryRegion(0, 1)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 2)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(2, 3)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(3, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(4, 5)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(5, 6)) == 0);

        REQUIRE(s.num_intersections(MemoryRegion(1, 3)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(2, 4)) == 2);
        REQUIRE(s.num_intersections(MemoryRegion(3, 5)) == 1);
    }

    SECTION("insert two intersecting elements") {
        s = {};
        AnnotatedMemoryRegion<int> a(1, 3, 42);
        AnnotatedMemoryRegion<int> b(2, 4, 43);
        s.insert(a);
        REQUIRE(s.size() == 1);
        s.insert(b);
        REQUIRE(s.size() == 2);


        REQUIRE(s.num_intersections(MemoryRegion(0, 1)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 2)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(2, 3)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(3, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(4, 5)) == 0);

        REQUIRE(s.num_intersections(MemoryRegion(1, 3)) == 2);
        REQUIRE(s.num_intersections(MemoryRegion(1, 4)) == 2);
        REQUIRE(s.num_intersections(MemoryRegion(2, 4)) == 1);
    }

    SECTION("insert enclosing intervals variant 1") {
        s = {};
        AnnotatedMemoryRegion<int> a(1, 4, 42);
        AnnotatedMemoryRegion<int> b(2, 3, 43);
        s.insert(a);
        REQUIRE(s.size() == 1);
        s.insert(b);
        REQUIRE(s.size() == 3);

        REQUIRE(s.num_intersections(MemoryRegion(0, 1)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 2)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(2, 3)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(3, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(4, 5)) == 0);

        REQUIRE(s.num_intersections(MemoryRegion(1, 3)) == 2);
        REQUIRE(s.num_intersections(MemoryRegion(1, 4)) == 3);
        REQUIRE(s.num_intersections(MemoryRegion(2, 4)) == 2);
    }

    SECTION("insert enclosing intervals variant 2") {
        s = {};
        AnnotatedMemoryRegion<int> a(2, 3, 42);
        AnnotatedMemoryRegion<int> b(1, 4, 43);
        s.insert(a);
        REQUIRE(s.size() == 1);
        s.insert(b);
        REQUIRE(s.size() == 1);

        REQUIRE(s.num_intersections(MemoryRegion(0, 1)) == 0);
        REQUIRE(s.num_intersections(MemoryRegion(1, 2)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(2, 3)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(3, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(4, 5)) == 0);

        REQUIRE(s.num_intersections(MemoryRegion(1, 3)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(1, 4)) == 1);
        REQUIRE(s.num_intersections(MemoryRegion(2, 4)) == 1);
    }

    SECTION("overwrite overlapping interval") {
        AnnotatedMemoryRegion<int> a(3, 5, 42);
        AnnotatedMemoryRegion<int> b(3, 5, 43);
        s.insert(a);
        REQUIRE(s.size() == 1);
        s.insert(b);
        REQUIRE(s.size() == 1);
    }
}
