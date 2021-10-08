#include <catch2/catch.hpp>
#include <android/logging.h>
#include <debugger/vex/IRSBResult.h>
#include <debugger/vex/VEXLifter.h>
#include <android/Debugging.h>
#include <vector>
#include <debugger/arch/aarch64.h>

[[clang::optnone]]
int dummy() {
    int i = 32;
    int j = 64;
    printf("%d %d", i, j);
    return 42;
}

TEST_CASE("Instruction access flags") {
    SECTION("Disassemble test") {
        unsigned char ins[] = {
                0xa0, 0x01, 0x9e, 0xd2, /* mov x0, #0xf00d */
                0x20, 0x00, 0x40, 0xf9, /* ldr x0, [x1] */
                0x20, 0x40, 0x40, 0xf8, /* ldr x0, [x1, #4] */
                0x20, 0x68, 0x62, 0xf8, /* ldr x0, [x1, x2] */
                0x20, 0x78, 0x62, 0xf8, /* ldr x0, [x1, x2, lsl #3] */
                0x30, 0x00, 0xdf, 0x4c, /* ld4 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64 */
                0x20, 0x00, 0x02, 0x0b, /* add w0, w1, w2 */
                0x20, 0x00, 0x01, 0x8b, /* add w0, w1, w1 */
                0x13, 0xd9, 0x29, 0xb8, /* str	w19, [x8, w9, sxtw #2] */
                0x23, 0x74, 0x0b, 0xd5, /* dc ZVA, x3 */
        };
        auto lifter = VEXLifter::get_instance();
        auto irsb_res = lifter.analyze(ins, sizeof(ins), (uint64_t) 0x1000);
        for (size_t i = 0; i < sizeof(ins) / 4; i++) {
            auto gm = irsb_res.get_guest_modifications(i, [](Int reg_offset) { return 0xdead000000000000;} );
            for (auto &m : gm.rw_pairs) {
                LOGE("Guest write: %s", m.write.str().c_str());
                for (auto &r : m.reads) {
                    LOGE("Guest read: %s", r.str().c_str());
                }
            }
            CHECK(gm.unused_reads.empty());
        }
    }
}

TEST_CASE("Unused reads") {
    unsigned char ins[] = {
            0xbf, 0x02, 0x40, 0xb9, /* ldr wzr, [x21] */
            0x20, 0x00, 0x40, 0xf9, /* ldr x0, [x1] */
    };
    auto lifter = VEXLifter::get_instance();
    auto irsb_res = lifter.analyze(ins, sizeof(ins), (uint64_t) 0x1000);

    auto gm0 = irsb_res.get_guest_modifications(0, [](Int reg_offset) { return 0xf00d;} );
    auto gm1 = irsb_res.get_guest_modifications(1, [](Int reg_offset) { return 0xf00d;} );

    CHECK(gm0.unused_reads.size() == 2);
    for (const auto r : gm1.unused_reads) {
        irsb_res.print_IRSB();
        LOGD("UNUSED READ %s", r.str().c_str());
    }
    CHECK(gm1.unused_reads.empty());

}

TEST_CASE("Disabled VEX optimizer") {
    SECTION("No shared temporaries between instructions") {
        // TODO: We can add assertions in IRSBResult::get_guest_modifications
        //       to check if any visited IR statements is from another instruction
        unsigned char ins[] = {
                0x6c, 0x01, 0x40, 0x39, /* ldrb w12,[x11] */
                0x8d, 0xfd, 0x43, 0xd3, /* lsr x13, x12, #3 */
        };
        auto lifter = VEXLifter::get_instance();
        auto irsb_res = lifter.analyze(ins, sizeof(ins), reinterpret_cast<uint64_t>(ins));
        irsb_res.print_IRSB();
        auto gm = irsb_res.get_guest_modifications(1, [](Int reg_offset) { return 0xdead000000000000;} );
        for (auto &m : gm.rw_pairs) {
            LOGE("Guest write: %s", m.write.str().c_str());
            for (auto &r : m.reads) {
                if (r.target == AccessTarget::Memory) {
                    CHECK(!"lsr reads memory from previous ldrb instruction");
                }
            }
        }
    }
}

TEST_CASE("Jump addresses") {
    uint64_t ip = 0x1000;
    auto lifter = VEXLifter::get_instance();
    SECTION("Static jump address") {
        unsigned char ins[] = {
                0x81, 0xfe, 0xff, 0x54, /* b.ne pc - 0x30 */
        };
        auto irsb_res = lifter.analyze(ins, sizeof(ins), ip);
        auto jump_targets = irsb_res.get_jump_targets();
        auto jump_addrs = std::vector<uint64_t> {};
        for (const auto &t : jump_targets) {
            REQUIRE(t->is_static_target());
            jump_addrs.push_back(t->get_target());
        }
        CHECK(std::find(jump_addrs.begin(), jump_addrs.end(), 0x1004) != jump_addrs.end());
        CHECK(std::find(jump_addrs.begin(), jump_addrs.end(), ip - 0x30) != jump_addrs.end());
    }
    SECTION("Dynamic jump address: branch linked reg") {
        unsigned char ins[] = {
                0x00, 0x00, 0x1f, 0xd6, /* blr x0 */
        };
        auto irsb_res = lifter.analyze(ins, sizeof(ins), ip);
        auto jump_targets = irsb_res.get_jump_targets();
        REQUIRE(jump_targets.size() == 1);
        CHECK(!jump_targets[0]->is_static_target());
    }

    SECTION("Dynamic jump address: return") {
        unsigned char ins[] = {
                0xc0, 0x03, 0x5f, 0xd6, /* blr x0 */
        };
        auto irsb_res = lifter.analyze(ins, sizeof(ins), ip);
        auto jump_targets = irsb_res.get_jump_targets();
        REQUIRE(jump_targets.size() == 1);
        CHECK(!jump_targets[0]->is_static_target());
    }
}

TEST_CASE("Get instruction address") {
    auto lifter = VEXLifter::get_instance();
    unsigned char ins[] = {
            0xa0, 0x01, 0x9e, 0xd2, /* mov x0, #0xf00d */
    };
    SECTION("Low address") {
        uint64_t ip = 0x1000;
        auto irsb_res = lifter.analyze(ins, sizeof(ins), ip);
        CHECK(irsb_res.get_instruction_address(0) == ip);
    }
    SECTION("High address") {
        uint64_t ip = 0x7161399080;
        auto irsb_res = lifter.analyze(ins, sizeof(ins), ip);
        CHECK(irsb_res.get_instruction_address(0) == ip);
        // Note that printing the IRSB will print the 64-bit address as a 32-bit address for the
        // IMark statement because the implementation of LibVEX uses a custom version of printf,
        // namely vprint_wrk which always formats %l as 32-bit instead of 64-bit on AArch64
    }
}

TEST_CASE("Instruction kind") {
    uint64_t ip = 0x1000;
    auto lifter = VEXLifter::get_instance();
    SECTION("Breakpoint") {
        const unsigned char *ins = aarch64::breakpoint_instruction.data();
        auto irsb_res = lifter.analyze(ins, aarch64::breakpoint_instruction.size(), ip);
        CHECK(irsb_res.get_jump_kind() == Ijk_SigTRAP);
    }

    SECTION("clrex") {
        const unsigned char *ins = aarch64::clear_exclusive_instruction.data();
        auto irsb_res = lifter.analyze(ins, aarch64::clear_exclusive_instruction.size(), ip);
        CHECK(irsb_res.get_llsc_kind(0) == LLSC_Kind::CLEAR_EXCLUSIVE);
    }
}
