#include <android/logging.h>
#include <cstdlib>
#include <stdexcept>
#include <debugger/arch/aarch64.h>
#include "VEXLifter.h"
#include <fmt/format.h>

/* VEX callbacks */
__attribute__((noreturn))
static void failure_exit() {
    LOGE("Failure exit called by libVEX");
    exit(1);
}

static void log_bytes(const HChar *bytes, SizeT nbytes) {
    android_printf("%.*s", nbytes, bytes);
}

static Bool chase_into_ok(void *closureV, Addr addr64) {
    return False;
}

static UInt needs_self_check(void *callback_opaque, VexRegisterUpdates *pxControl,
                                 const VexGuestExtents *guest_extents) {
    return 0;
}

static void *dispatch(void) {
    return nullptr;
}

void VEXLifter::vex_prepare_vai(VexArch arch, VexArchInfo *vai) {
    switch (arch) {
        case VexArchX86:
            vai->hwcaps =   VEX_HWCAPS_X86_MMXEXT |
                            VEX_HWCAPS_X86_SSE1 |
                            VEX_HWCAPS_X86_SSE2 |
                            VEX_HWCAPS_X86_SSE3 |
                            VEX_HWCAPS_X86_LZCNT;
            break;
        case VexArchAMD64:
            vai->hwcaps =   VEX_HWCAPS_AMD64_SSE3 |
                            VEX_HWCAPS_AMD64_CX16 |
                            VEX_HWCAPS_AMD64_LZCNT |
                            VEX_HWCAPS_AMD64_AVX |
                            VEX_HWCAPS_AMD64_RDTSCP |
                            VEX_HWCAPS_AMD64_BMI |
                            VEX_HWCAPS_AMD64_AVX2;
            break;
        case VexArchARM:
            vai->hwcaps = VEX_ARM_ARCHLEVEL(8) |
                          VEX_HWCAPS_ARM_NEON |
                          VEX_HWCAPS_ARM_VFP3;
            break;
        case VexArchARM64:
            vai->hwcaps = 0;
            vai->arm64_dMinLine_lg2_szB = 6;
            vai->arm64_iMinLine_lg2_szB = 6;
            break;
        case VexArchPPC32:
            vai->hwcaps =   VEX_HWCAPS_PPC32_F |
                            VEX_HWCAPS_PPC32_V |
                            VEX_HWCAPS_PPC32_FX |
                            VEX_HWCAPS_PPC32_GX |
                            VEX_HWCAPS_PPC32_VX |
                            VEX_HWCAPS_PPC32_DFP |
                            VEX_HWCAPS_PPC32_ISA2_07;
            vai->ppc_icache_line_szB = 32; // unsure if correct
            break;
        case VexArchPPC64:
            vai->hwcaps =   VEX_HWCAPS_PPC64_V |
                            VEX_HWCAPS_PPC64_FX |
                            VEX_HWCAPS_PPC64_GX |
                            VEX_HWCAPS_PPC64_VX |
                            VEX_HWCAPS_PPC64_DFP |
                            VEX_HWCAPS_PPC64_ISA2_07;
            vai->ppc_icache_line_szB = 64; // unsure if correct
            break;
        case VexArchS390X:
            vai->hwcaps = 0;
            break;
        case VexArchMIPS32:
        case VexArchMIPS64:
            vai->hwcaps = VEX_PRID_COMP_CAVIUM;
            break;
        default:
            throw std::runtime_error("Invalid arch in vex_prepare_vai.");
    }
}

void VEXLifter::vex_prepare_vbi(VexArch arch, VexAbiInfo *vbi) {
    // only setting the guest_stack_redzone_size for now
    // this attribute is only specified by the X86, AMD64 and PPC64 ABIs
    switch (arch) {
        case VexArchX86:
            vbi->guest_stack_redzone_size = 0;
            break;
        case VexArchAMD64:
            vbi->guest_stack_redzone_size = 128;
            break;
        case VexArchPPC64:
            vbi->guest_stack_redzone_size = 288;
            break;
        default:
            break;
    }
}

VEXLifter::VEXLifter() {
    /*
     * Vex initialization code largely based on pyvex of the angr project.
     *
     * Vine is Copyright (C) 2006-2009, BitBlaze Team.
     * You can redistribute and modify it under the terms of the GNU GPL,
     * version 2 or later, but it is made available WITHOUT ANY WARRANTY.
     * See the top-level README file for more details.
     * For more information about Vine and other BitBlaze software, see our
     * web site at: http://bitblaze.cs.berkeley.edu/
     */
    LOGD("Initializing VEX.");

    // Initialize VEX
    LibVEX_default_VexControl(&vc_);
    LibVEX_default_VexArchInfo(&vai_host_);
    LibVEX_default_VexAbiInfo(&vbi_);

    vc_.iropt_verbosity              = 0;
    vc_.iropt_level                  = 0;    // No optimization by default
    /*
     * Make sure that used temporaries for 1 instruction transitively have an assignment
     * within that instruction, instead of a temporary being dependent on a memory read of the
     * previous instruction
     */
    vc_.iropt_remove_redundant_get   = False;
    //vc_.iropt_precise_memory_exns    = False;
    vc_.iropt_unroll_thresh          = 0;
    vc_.guest_max_insns              = 1;    // By default, we vex 1 instruction at a time

    // /* angr options */
    // vc_.guest_chase_thresh           = 0;
    // vc_.arm64_allow_reordered_writeback = 0;
    // vc_.x86_optimize_callpop_idiom = 0;
    // vc_.strict_block_end = 0;

    LOGD("Calling LibVEX_Init()....");
    // the 0 is the debug level
    LibVEX_Init(&failure_exit, &log_bytes, 0, &vc_);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    vai_host_.endness = VexEndnessLE;
#else
    vai_host_.endness = VexEndnessBE;
#endif

    // various settings to make stuff work
    // ... former is set to 'unspecified', but gets set in vex_inst for archs which care
    // ... the latter two are for dealing with gs and fs in VEX
    vbi_.guest_stack_redzone_size = 0;
    vbi_.guest_amd64_assume_fs_is_const = True;
    vbi_.guest_amd64_assume_gs_is_const = True;

    //------------------------------------
    // options for instruction translation

    //
    // Architecture info
    //
    vta_.arch_guest          = VexArch_INVALID; // to be assigned later
#if __amd64__ || _WIN64
    vta_.arch_host = VexArchAMD64;
#elif __i386__ || _WIN32
    vta_.arch_host = VexArchX86;
#elif __arm__
    vta_.arch_host = VexArchARM;
	vai_host_.hwcaps = 7;
#elif __aarch64__
    vta_.arch_host = VexArchARM64;
#elif __s390x__
    vta_.arch_host = VexArchS390X;
	vai_host_.hwcaps = VEX_HWCAPS_S390X_LDISP;
#else
#error "Unsupported host arch"
#endif

    vta_.archinfo_host = vai_host_;

    //
    // The actual stuff to vex
    //
    vta_.guest_bytes         = NULL;             // Set in vex_lift
    vta_.guest_bytes_addr    = 0;                // Set in vex_lift

    //
    // callbacks
    //
    vta_.callback_opaque     = NULL;             // Used by chase_into_ok, but never actually called
    vta_.chase_into_ok       = chase_into_ok;    // Always returns false
    vta_.preamble_function   = NULL;
    vta_.instrument1         = NULL;
    vta_.instrument2         = NULL;
    vta_.finaltidy	    	= NULL;
    vta_.needs_self_check	= needs_self_check;

    vta_.disp_cp_chain_me_to_slowEP = (void *)dispatch; // Not used
    vta_.disp_cp_chain_me_to_fastEP = (void *)dispatch; // Not used
    vta_.disp_cp_xindir = (void *)dispatch; // Not used
    vta_.disp_cp_xassisted = (void *)dispatch; // Not used

    vta_.guest_extents       = &vge_;
    vta_.host_bytes          = NULL;           // Buffer for storing the output binary
    vta_.host_bytes_size     = 0;
    vta_.host_bytes_used     = NULL;
    // doesn't exist? vta_.do_self_check       = False;
    vta_.traceflags          = 0;                // Debug verbosity
    //vta_.traceflags          = -1;                // Debug verbosity
    vta_.sigill_diag         = 1;
    vta_.addProfInc          = 0;
}

IRSB *VEXLifter::vex_lift(
        VexArch guest,
        VexArchInfo archinfo,
        unsigned char *insn_start,
        unsigned long long insn_addr,
        unsigned int max_insns,
        unsigned int max_bytes,
        int opt_level,
        int traceflags,
        int allow_arch_optimizations,
        int strict_block_end) {
    VexRegisterUpdates pxControl;

    vex_prepare_vai(guest, &archinfo);
    vex_prepare_vbi(guest, &vbi_);

    LOGD("Guest arch: %d", guest);
    LOGD("Guest arch hwcaps: %08x", archinfo.hwcaps);

    vta_.archinfo_guest = archinfo;
    vta_.arch_guest = guest;
    vta_.abiinfo_both = vbi_; // Set the vbi_ value

    vta_.guest_bytes         = (UChar *)(insn_start);  // Ptr to actual bytes of start of instruction
    vta_.guest_bytes_addr    = (Addr64)(insn_addr);
    vta_.traceflags          = traceflags;

    // max_bytes is unused!
    vc_.guest_max_insns = max_insns;

    /* angr allows vc_ to be modified before each analysis */
    // vc_.guest_max_bytes     = max_bytes;
    // vc_.guest_max_insns     = max_insns;
    // vc_.iropt_level         = opt_level;

    // // Gate all of these on one flag, they depend on the arch
    // vc_.arm_allow_optimizing_lookback = allow_arch_optimizations;
    // vc_.arm64_allow_reordered_writeback = allow_arch_optimizations;
    // vc_.x86_optimize_callpop_idiom = allow_arch_optimizations;

    // vc_.strict_block_end = strict_block_end;

    LibVEX_Update_Control(&vc_);
    IRSB *res = LibVEX_FrontEnd(&vta_, &vtr_, &pxControl);
    // IRSB *res = LibVEX_Lift(&vta_, &vtr_, &pxControl); // angr lift
    if (!res) {
        throw std::runtime_error("libVEX lifting failed: returned nullptr");
    }
    return res;
}

VEXLifter &VEXLifter::get_instance() {
    static VEXLifter instance {};
    return instance;
}

size_t next_irsb_id = 0;

size_t VEXLifter::get_irsb_id_alive() {
    return next_irsb_id - 1;
}

IRSBResult VEXLifter::analyze(const uint8_t *code, size_t size, uint64_t ip) {
    VexArchInfo archInfo {
            .hwcaps = 0,
            .endness = VexEndnessLE,
            .hwcache_info = {
                    .num_levels = 0,
                    .num_caches = 0,
                    .caches = nullptr,
                    .icaches_maintain_coherence = 1
            },
            .ppc_dcbz_szB = 0,
            .ppc_dcbzl_szB = 0,
            .ppc_icache_line_szB = 0,
            // .x86_cr0 = 0, // angr
            .arm64_requires_fallback_LLSC = 0,
            .arm64_dMinLine_lg2_szB = 0,
            .arm64_iMinLine_lg2_szB = 0,

    };
    assert (size % aarch64::instruction_size == 0);
    auto ins_count = size / aarch64::instruction_size;
    IRSB *irsb = vex_lift(VexArchARM64, archInfo, (uint8_t *) code, ip,
                               (unsigned int) ins_count,
                               (unsigned int)size, 0, 0, 0, 1);
    if (irsb == nullptr) {
        throw std::runtime_error("vex_lift returned nullptr");
    }
    auto machine_instructions = std::vector<uint32_t>();
    machine_instructions.reserve(ins_count);
    for (size_t i = 0; i < ins_count; i++) {
        machine_instructions.emplace_back(*(uint32_t *)(code + i * sizeof(uint32_t)));
    }

    auto res = IRSBResult(irsb, std::move(machine_instructions), next_irsb_id++);
    auto analyzed_ins_count = res.ins_count_;
    if (size < aarch64::instruction_size * analyzed_ins_count) {
        throw std::runtime_error("vex_lift analyzed more instructions than we provided");
    }
    if (irsb->jumpkind == IRJumpKind::Ijk_NoDecode) {
        if (analyzed_ins_count < 1) {
            throw std::runtime_error("Assumption violated: NoDecode should have at least 1 instruction");
        }
        uint32_t last_instruction = *(uint32_t *)(code + aarch64::instruction_size * (analyzed_ins_count - 1));

        uint32_t ldxp_bits = (1u << 31) | (0b001000011111110 << 15);
        uint32_t ldxp_mask = (1u << 31) | (0b001111111111111 << 15);
        uint32_t ldaxp_bits = (1u << 31) | (0b001000011111111 << 15);
        uint32_t ldaxp_mask = (1u << 31) | (0b001111111111111 << 15);
        uint32_t stxp_bits = (1u << 31) | (0b001000001 << 21);
        uint32_t stxp_mask = (1u << 31) | (0b111111111 << 21) | (1u << 15);
        uint32_t stlxp_bits = (1u << 31) | (0b001000001 << 21) | (1u << 15);
        uint32_t stlxp_mask = (1u << 31) | (0b111111111 << 21) | (1u << 15);
        if (0 == (ldxp_mask & (last_instruction ^ ldxp_bits))) {
            // ARM Architecture Reference Manual ARMv8 C6.2.161
            LOGW("Upstream valgrind can't decode LDXP yet, overriding LLSC kind for now...");
            res.override_llsc_kind(analyzed_ins_count - 1, LLSC_Kind::LOAD_LINKED);
        } else if (0 == (ldaxp_mask & (last_instruction ^ ldaxp_bits))) {
            // ARM Architecture Reference Manual ARMv8 C6.2.103
            LOGW("Upstream valgrind can't decode LADXP yet, overriding LLSC kind for now...");
            res.override_llsc_kind(analyzed_ins_count - 1, LLSC_Kind::LOAD_LINKED);
        } else if (0 == (stxp_mask & (last_instruction ^ stxp_bits))) {
            // ARM Architecture Reference Manual ARMv8 C6.2.284
            LOGW("Upstream valgrind can't decode STXP yet, overriding STXP kind for now...");
            res.override_llsc_kind(analyzed_ins_count - 1, LLSC_Kind::STORE_CONDITIONAL);
        } else if (0 == (stlxp_mask & (last_instruction ^ stlxp_bits))) {
            // ARM Architecture Reference Manual ARMv8 C6.2.251
            LOGW("Upstream valgrind can't decode STLXP yet, overriding STXP kind for now...");
            res.override_llsc_kind(analyzed_ins_count - 1, LLSC_Kind::STORE_CONDITIONAL);
        } else if (aarch64::is_dc_zva(last_instruction)) {
            LOGW("Upstream valgrind can't decode dc ZVA yet, overriding memory accesses for now");
        } else {
                res.print_IRSB();
                throw std::runtime_error(
                        fmt::format("Unable to decode basic block as IRSB. Failing instruction: {:#x} Check upstream repo for updates.", last_instruction));
        }
    }
    return res;
}
