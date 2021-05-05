#pragma once

#include "IRSBResult.h"

extern "C" {
#include <libvex.h>
}

class VEXLifter {
private:
    /**
     * Must only be called once, namely by VEXLifter::get_instance
     */
    VEXLifter();
    VexArchInfo         vai_host_;
    VexGuestExtents     vge_;
    VexTranslateArgs    vta_;
    VexTranslateResult  vtr_;
    VexAbiInfo	        vbi_;
    VexControl          vc_;

    void vex_prepare_vai(VexArch arch, VexArchInfo *vai);
    void vex_prepare_vbi(VexArch arch, VexAbiInfo *vbi);

    IRSB *vex_lift(VexArch guest, VexArchInfo archinfo, unsigned char *insn_start,
                   unsigned long long int insn_addr, unsigned int max_insns, unsigned int max_bytes,
                   int opt_level, int traceflags, int allow_arch_optimizations,
                   int strict_block_end);
public:
    static VEXLifter &get_instance();
    static size_t get_irsb_id_alive();
    /**
     * Analyze a block of code with libVEX.
     * @param code Pointer to machine instructions
     * @param size Size of machine instruction block
     * @param ip Virtual address of the first instruction of the target process
     */
    IRSBResult analyze(const uint8_t *code, size_t size, uint64_t ip);
};
