#include <catch2/catch.hpp>
#include <sys/mman.h>

TEST_CASE("mmap allows accesses with offset larger than requested length") {
    char *buf = (char *) mmap((void *)0x42000, 42, PROT_READ | PROT_WRITE,
                                         MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    buf[4095] = 5; // Can write outside requested region of 42 bytes
    REQUIRE(buf[4095] == 5);

    REQUIRE(-1 != munmap((void *)0x42000, 1));
    /*
     * According to the manpage: All pages containing a part of the indicated range are unmapped
     * This means the following will cause a segfault
     */
    // REQUIRE(buf[4095] == 5);
}

TEST_CASE("anonymous shared memory persists, even after partial unmap") {
    char constexpr magic = 0xa;
    char *buf = (char *) mmap((void *) 0x42000, 0x2000, PROT_READ | PROT_WRITE,
                                         MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED, 0, 0);
    buf[0x1000] = magic;
    REQUIRE(munmap((void *) 0x43000, 0x1000) != -1);
    buf = (char *) mremap(buf, 0, 0x2000, MREMAP_MAYMOVE | MREMAP_FIXED, 0x62000);
    REQUIRE(buf != (char *) -1);
    REQUIRE(buf[0x1000] == magic);
}

TEST_CASE("mremap requires contiguous vm_area_struct") {
    char *buf = (char *) mmap(0, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    REQUIRE(buf != (void *) -1);
    buf[PAGE_SIZE] = 0x42;

    REQUIRE(-1 != mprotect(buf, PAGE_SIZE, PROT_NONE));
    REQUIRE(-1 != mprotect(buf + PAGE_SIZE, PAGE_SIZE, PROT_NONE)); // Commenting this causes mremap to fail
    REQUIRE((void *) -1 != mremap(buf, 2 * PAGE_SIZE, 3 * PAGE_SIZE, MREMAP_FIXED | MREMAP_MAYMOVE, 0x42000));
    REQUIRE(-1 != mprotect((char *) 0x42000 + PAGE_SIZE, PAGE_SIZE, PROT_READ));
    REQUIRE(*(char *) (0x42000 + PAGE_SIZE) == 0x42);

    REQUIRE(-1 != munmap((void *) 0x42000, 3 * PAGE_SIZE));
}