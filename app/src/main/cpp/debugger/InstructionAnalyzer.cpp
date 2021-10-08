#include <android/logging.h>
#include "InstructionAnalyzer.h"
#include "Config.h"
#include <iostream>
#include <capstone/arm64.h>
#include <fmt/format.h>
#include <magic_enum.hpp>
#include <debugger/taint/AnnotatedAddressSpace.h>
#include <set>
#include <debugger/vex/VEXLifter.h>

AnalysisResult::AnalysisResult(InstructionAnalyzer *analyzer, cs_insn *ins, size_t count,
                               IRSBResult irsb) : CapstoneAnalysisResult(analyzer, ins, count),
                                                  irsb_(std::move(irsb)) {
    if (Config::print_instructions) {
        get_irsb().print_IRSB();
    }
}

AnalysisResult &AnalysisResult::operator=(AnalysisResult &&rhs) {
    irsb_ = std::move(rhs.irsb_);
    CapstoneAnalysisResult::operator=(std::move(rhs));
    return *this;
}

CapstoneAnalysisResult& CapstoneAnalysisResult::operator=(CapstoneAnalysisResult && rhs) {
    analyzer_ = rhs.analyzer_;
    ins_ = rhs.ins_;
    count_ = rhs.count_;

    rhs.ins_ = nullptr;
    return *this;
}

std::pair<unsigned char *, size_t> CapstoneAnalysisResult::get_machine_bytes(size_t ins_i) const {
    return std::pair(ins_[ins_i].bytes, ins_[ins_i].size);
}

std::string CapstoneAnalysisResult::to_string(size_t ins_i) const {
    return fmt::format("{} {}", ins_[ins_i].mnemonic, ins_[ins_i].op_str);
}

void CapstoneAnalysisResult::print_instruction(size_t ins_i) const {
    LOGV("%" PRIx64 "\t%s\t%s", instruction_address(ins_i), ins_[ins_i].mnemonic, ins_[ins_i].op_str);
}

void CapstoneAnalysisResult::print_instructions() const {
    for (size_t i = 0; i < count_; i++) {
        print_instruction(i);
    }
}

uint64_t CapstoneAnalysisResult::instruction_address(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to get instruction address for an out-of-bounds instruction");
    }
    return ins_[ins_i].address;
}

bool CapstoneAnalysisResult::is_memory_access(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to get memory access for an out-of-bounds instruction");
    }
    if (analyzer_->arch == ProcessArchitecture::ARM64) {
        cs_arm64& arm_ins = ins_[ins_i].detail->arm64;
        if (aarch64::is_dc_zva(*(uint32_t *)ins_[ins_i].bytes)) {
            LOGW("Overriding Capstone is_memory_access for dc ZVA");
            return true;
        }
        for (uint8_t i = 0; i < arm_ins.op_count; i++) {
            cs_arm64_op &op = arm_ins.operands[i];
            if (op.type == ARM64_OP_MEM) {
                return true;
            }
        }
        return false;
    } else {
        throw std::runtime_error("NYI: unknown architecture");
    }
}

bool CapstoneAnalysisResult::is_breakpoint(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to get memory access for an out-of-bounds instruction");
    }
    if (analyzer_->arch == ProcessArchitecture::ARM64) {
        uint8_t *arm_ins = ins_[ins_i].bytes;
        if (ins_[ins_i].size == aarch64::breakpoint_instruction.size()) {
            // Size matches
            if (std::equal(aarch64::breakpoint_instruction.data(), aarch64::breakpoint_instruction.data() + aarch64::breakpoint_instruction.size(), arm_ins)) {
                // Contents match
                return true;
            }
        }
        return false;
    } else {
        throw std::runtime_error("NYI: unknown architecture");
    }
}

std::optional<GuestAccess>
AnalysisResult::memory_accesses(size_t ins_i, AArch64RegisterState &regs) {
    auto &irsb = get_irsb();

    auto guest_modifications = irsb.get_guest_modifications(ins_i, [&](Int reg_offset) {
        return regs.read_from_vex_offset(reg_offset);
    });
    std::optional<AccessType> type {};
    std::vector<MemoryRegion> regions {};
    auto add_mem_access = [&] (MemoryRegion r, AccessType t) {
        if (type && *type != t) {
            assert(!regions.empty());
            if (regions[0] == r) {
                return; // Allow LLSC instructions
            } else {
                if (Config::print_instructions) {
                    print_instruction(ins_i);
                }
                throw std::runtime_error("Single instruction contains different memory accesses with at least 1 read and at least 1 write");
            }
        }
        type = t;
        regions.push_back(r);
    };

    // Merge neighboring memory accesses reported by VEX into 1 large memory region
    guest_modifications.for_each_mem_access([&] (const GuestAccess &a) {
        add_mem_access(a.region, a.type);
    });

    if (regions.empty()) {
        return {};
    } else {
        return GuestAccess(merge_consecutive_regions(regions), AccessTarget::Memory, type.value());
    }
}

std::optional<MemoryAccess> CapstoneAnalysisResult::capstone_memory_accesses(size_t ins_i, AArch64RegisterState &regs) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to get memory access for an out-of-bounds instruction");
    }
    if (analyzer_->arch == ProcessArchitecture::ARM64) {
        cs_arm64& arm_ins = ins_[ins_i].detail->arm64;
        std::vector<std::reference_wrapper<cs_arm64_op>> mem_ops {};

        for (uint8_t i = 0; i < arm_ins.op_count; i++) {
            cs_arm64_op &op = arm_ins.operands[i];
            if (op.type == ARM64_OP_MEM) {
                mem_ops.push_back(std::ref(op));
            }
        }

        if (mem_ops.empty()) {
            return {};
        }
        if (mem_ops.size() > 1) {
            throw std::runtime_error("Assumption violated: only 1 memory access per instruction");
        }

        cs_arm64_op &op = mem_ops.begin()->get();
        uint64_t mem_addr = 0;
        MemoryAccessType access;
        if (op.mem.base != ARM64_REG_INVALID) {
            mem_addr += regs[op.mem.base];
        }
        if (op.shift.type != ARM64_SFT_INVALID) {
            // TODO: Support SXTW shift mode
            if (op.shift.type != ARM64_SFT_LSL)
                throw std::runtime_error("NYI: non-LSL index shift for memory accesses");
            if(op.mem.index == ARM64_REG_INVALID)
                throw std::runtime_error("NYI: shift operand on non-index register");
            if(op.mem.disp != 0)
                throw std::runtime_error("Assumption violated: displacement register was used in memory access with shift!");
            mem_addr += regs[op.mem.index] * (1 << op.shift.value);
        } else if (op.mem.index != ARM64_REG_INVALID) {
            mem_addr += regs[op.mem.index] + op.mem.disp;
        }

        /*
         * Capstone can report LD* instructions with READ|WRITE access type instead of READ
         * Capstone can report ST* instructions with READ|WRITE access type instead of WRITE
         */
        auto ins_id = (arm64_insn) ins_[ins_i].id;
        switch (ins_id) {
            case ARM64_INS_LD1:
            case ARM64_INS_LD1B:
            case ARM64_INS_LD1D:
            case ARM64_INS_LD1H:
            case ARM64_INS_LD1R:
            case ARM64_INS_LD1RB:
            case ARM64_INS_LD1RD:
            case ARM64_INS_LD1RH:
            case ARM64_INS_LD1RQB:
            case ARM64_INS_LD1RQD:
            case ARM64_INS_LD1RQH:
            case ARM64_INS_LD1RQW:
            case ARM64_INS_LD1RSB:
            case ARM64_INS_LD1RSH:
            case ARM64_INS_LD1RSW:
            case ARM64_INS_LD1RW:
            case ARM64_INS_LD1SB:
            case ARM64_INS_LD1SH:
            case ARM64_INS_LD1SW:
            case ARM64_INS_LD1W:
            case ARM64_INS_LD2:
            case ARM64_INS_LD2B:
            case ARM64_INS_LD2D:
            case ARM64_INS_LD2H:
            case ARM64_INS_LD2R:
            case ARM64_INS_LD2W:
            case ARM64_INS_LD3:
            case ARM64_INS_LD3B:
            case ARM64_INS_LD3D:
            case ARM64_INS_LD3H:
            case ARM64_INS_LD3R:
            case ARM64_INS_LD3W:
            case ARM64_INS_LD4:
            case ARM64_INS_LD4B:
            case ARM64_INS_LD4D:
            case ARM64_INS_LD4H:
            case ARM64_INS_LD4R:
            case ARM64_INS_LD4W:
            case ARM64_INS_LDADD:
            case ARM64_INS_LDADDA:
            case ARM64_INS_LDADDAB:
            case ARM64_INS_LDADDAH:
            case ARM64_INS_LDADDAL:
            case ARM64_INS_LDADDALB:
            case ARM64_INS_LDADDALH:
            case ARM64_INS_LDADDB:
            case ARM64_INS_LDADDH:
            case ARM64_INS_LDADDL:
            case ARM64_INS_LDADDLB:
            case ARM64_INS_LDADDLH:
            case ARM64_INS_LDAPR:
            case ARM64_INS_LDAPRB:
            case ARM64_INS_LDAPRH:
            case ARM64_INS_LDAPUR:
            case ARM64_INS_LDAPURB:
            case ARM64_INS_LDAPURH:
            case ARM64_INS_LDAPURSB:
            case ARM64_INS_LDAPURSH:
            case ARM64_INS_LDAPURSW:
            case ARM64_INS_LDAR:
            case ARM64_INS_LDARB:
            case ARM64_INS_LDARH:
            case ARM64_INS_LDAXP:
            case ARM64_INS_LDAXR:
            case ARM64_INS_LDAXRB:
            case ARM64_INS_LDAXRH:
            case ARM64_INS_LDCLR:
            case ARM64_INS_LDCLRA:
            case ARM64_INS_LDCLRAB:
            case ARM64_INS_LDCLRAH:
            case ARM64_INS_LDCLRAL:
            case ARM64_INS_LDCLRALB:
            case ARM64_INS_LDCLRALH:
            case ARM64_INS_LDCLRB:
            case ARM64_INS_LDCLRH:
            case ARM64_INS_LDCLRL:
            case ARM64_INS_LDCLRLB:
            case ARM64_INS_LDCLRLH:
            case ARM64_INS_LDEOR:
            case ARM64_INS_LDEORA:
            case ARM64_INS_LDEORAB:
            case ARM64_INS_LDEORAH:
            case ARM64_INS_LDEORAL:
            case ARM64_INS_LDEORALB:
            case ARM64_INS_LDEORALH:
            case ARM64_INS_LDEORB:
            case ARM64_INS_LDEORH:
            case ARM64_INS_LDEORL:
            case ARM64_INS_LDEORLB:
            case ARM64_INS_LDEORLH:
            case ARM64_INS_LDFF1B:
            case ARM64_INS_LDFF1D:
            case ARM64_INS_LDFF1H:
            case ARM64_INS_LDFF1SB:
            case ARM64_INS_LDFF1SH:
            case ARM64_INS_LDFF1SW:
            case ARM64_INS_LDFF1W:
            case ARM64_INS_LDLAR:
            case ARM64_INS_LDLARB:
            case ARM64_INS_LDLARH:
            case ARM64_INS_LDNF1B:
            case ARM64_INS_LDNF1D:
            case ARM64_INS_LDNF1H:
            case ARM64_INS_LDNF1SB:
            case ARM64_INS_LDNF1SH:
            case ARM64_INS_LDNF1SW:
            case ARM64_INS_LDNF1W:
            case ARM64_INS_LDNP:
            case ARM64_INS_LDNT1B:
            case ARM64_INS_LDNT1D:
            case ARM64_INS_LDNT1H:
            case ARM64_INS_LDNT1W:
            case ARM64_INS_LDP:
            case ARM64_INS_LDPSW:
            case ARM64_INS_LDR:
            case ARM64_INS_LDRAA:
            case ARM64_INS_LDRAB:
            case ARM64_INS_LDRB:
            case ARM64_INS_LDRH:
            case ARM64_INS_LDRSB:
            case ARM64_INS_LDRSH:
            case ARM64_INS_LDRSW:
            case ARM64_INS_LDSET:
            case ARM64_INS_LDSETA:
            case ARM64_INS_LDSETAB:
            case ARM64_INS_LDSETAH:
            case ARM64_INS_LDSETAL:
            case ARM64_INS_LDSETALB:
            case ARM64_INS_LDSETALH:
            case ARM64_INS_LDSETB:
            case ARM64_INS_LDSETH:
            case ARM64_INS_LDSETL:
            case ARM64_INS_LDSETLB:
            case ARM64_INS_LDSETLH:
            case ARM64_INS_LDSMAX:
            case ARM64_INS_LDSMAXA:
            case ARM64_INS_LDSMAXAB:
            case ARM64_INS_LDSMAXAH:
            case ARM64_INS_LDSMAXAL:
            case ARM64_INS_LDSMAXALB:
            case ARM64_INS_LDSMAXALH:
            case ARM64_INS_LDSMAXB:
            case ARM64_INS_LDSMAXH:
            case ARM64_INS_LDSMAXL:
            case ARM64_INS_LDSMAXLB:
            case ARM64_INS_LDSMAXLH:
            case ARM64_INS_LDSMIN:
            case ARM64_INS_LDSMINA:
            case ARM64_INS_LDSMINAB:
            case ARM64_INS_LDSMINAH:
            case ARM64_INS_LDSMINAL:
            case ARM64_INS_LDSMINALB:
            case ARM64_INS_LDSMINALH:
            case ARM64_INS_LDSMINB:
            case ARM64_INS_LDSMINH:
            case ARM64_INS_LDSMINL:
            case ARM64_INS_LDSMINLB:
            case ARM64_INS_LDSMINLH:
            case ARM64_INS_LDTR:
            case ARM64_INS_LDTRB:
            case ARM64_INS_LDTRH:
            case ARM64_INS_LDTRSB:
            case ARM64_INS_LDTRSH:
            case ARM64_INS_LDTRSW:
            case ARM64_INS_LDUMAX:
            case ARM64_INS_LDUMAXA:
            case ARM64_INS_LDUMAXAB:
            case ARM64_INS_LDUMAXAH:
            case ARM64_INS_LDUMAXAL:
            case ARM64_INS_LDUMAXALB:
            case ARM64_INS_LDUMAXALH:
            case ARM64_INS_LDUMAXB:
            case ARM64_INS_LDUMAXH:
            case ARM64_INS_LDUMAXL:
            case ARM64_INS_LDUMAXLB:
            case ARM64_INS_LDUMAXLH:
            case ARM64_INS_LDUMIN:
            case ARM64_INS_LDUMINA:
            case ARM64_INS_LDUMINAB:
            case ARM64_INS_LDUMINAH:
            case ARM64_INS_LDUMINAL:
            case ARM64_INS_LDUMINALB:
            case ARM64_INS_LDUMINALH:
            case ARM64_INS_LDUMINB:
            case ARM64_INS_LDUMINH:
            case ARM64_INS_LDUMINL:
            case ARM64_INS_LDUMINLB:
            case ARM64_INS_LDUMINLH:
            case ARM64_INS_LDUR:
            case ARM64_INS_LDURB:
            case ARM64_INS_LDURH:
            case ARM64_INS_LDURSB:
            case ARM64_INS_LDURSH:
            case ARM64_INS_LDURSW:
            case ARM64_INS_LDXP:
            case ARM64_INS_LDXR:
            case ARM64_INS_LDXRB:
            case ARM64_INS_LDXRH:
                access = MemoryAccessType::READ;
                break;

            case ARM64_INS_SABA:
            case ARM64_INS_SABAL:
            case ARM64_INS_SABAL2:
            case ARM64_INS_SABD:
            case ARM64_INS_SABDL:
            case ARM64_INS_SABDL2:
            case ARM64_INS_SADALP:
            case ARM64_INS_SADDL:
            case ARM64_INS_SADDL2:
            case ARM64_INS_SADDLP:
            case ARM64_INS_SADDLV:
            case ARM64_INS_SADDV:
            case ARM64_INS_SADDW:
            case ARM64_INS_SADDW2:
            case ARM64_INS_SBC:
            case ARM64_INS_SBCS:
            case ARM64_INS_SBFM:
            case ARM64_INS_SCVTF:
            case ARM64_INS_SDIV:
            case ARM64_INS_SDIVR:
            case ARM64_INS_SDOT:
            case ARM64_INS_SEL:
            case ARM64_INS_SETF16:
            case ARM64_INS_SETF8:
            case ARM64_INS_SETFFR:
            case ARM64_INS_SEV:
            case ARM64_INS_SEVL:
            case ARM64_INS_SHA1C:
            case ARM64_INS_SHA1H:
            case ARM64_INS_SHA1M:
            case ARM64_INS_SHA1P:
            case ARM64_INS_SHA1SU0:
            case ARM64_INS_SHA1SU1:
            case ARM64_INS_SHA256H:
            case ARM64_INS_SHA256H2:
            case ARM64_INS_SHA256SU0:
            case ARM64_INS_SHA256SU1:
            case ARM64_INS_SHA512H:
            case ARM64_INS_SHA512H2:
            case ARM64_INS_SHA512SU0:
            case ARM64_INS_SHA512SU1:
            case ARM64_INS_SHADD:
            case ARM64_INS_SHL:
            case ARM64_INS_SHLL:
            case ARM64_INS_SHLL2:
            case ARM64_INS_SHRN:
            case ARM64_INS_SHRN2:
            case ARM64_INS_SHSUB:
            case ARM64_INS_SLI:
            case ARM64_INS_SM3PARTW1:
            case ARM64_INS_SM3PARTW2:
            case ARM64_INS_SM3SS1:
            case ARM64_INS_SM3TT1A:
            case ARM64_INS_SM3TT1B:
            case ARM64_INS_SM3TT2A:
            case ARM64_INS_SM3TT2B:
            case ARM64_INS_SM4E:
            case ARM64_INS_SM4EKEY:
            case ARM64_INS_SMADDL:
            case ARM64_INS_SMAX:
            case ARM64_INS_SMAXP:
            case ARM64_INS_SMAXV:
            case ARM64_INS_SMC:
            case ARM64_INS_SMIN:
            case ARM64_INS_SMINP:
            case ARM64_INS_SMINV:
            case ARM64_INS_SMLAL:
            case ARM64_INS_SMLAL2:
            case ARM64_INS_SMLSL:
            case ARM64_INS_SMLSL2:
            case ARM64_INS_SMNEGL:
            case ARM64_INS_SMOV:
            case ARM64_INS_SMSUBL:
            case ARM64_INS_SMULH:
            case ARM64_INS_SMULL:
            case ARM64_INS_SMULL2:
            case ARM64_INS_SPLICE:
            case ARM64_INS_SQABS:
            case ARM64_INS_SQADD:
            case ARM64_INS_SQDECB:
            case ARM64_INS_SQDECD:
            case ARM64_INS_SQDECH:
            case ARM64_INS_SQDECP:
            case ARM64_INS_SQDECW:
            case ARM64_INS_SQDMLAL:
            case ARM64_INS_SQDMLAL2:
            case ARM64_INS_SQDMLSL:
            case ARM64_INS_SQDMLSL2:
            case ARM64_INS_SQDMULH:
            case ARM64_INS_SQDMULL:
            case ARM64_INS_SQDMULL2:
            case ARM64_INS_SQINCB:
            case ARM64_INS_SQINCD:
            case ARM64_INS_SQINCH:
            case ARM64_INS_SQINCP:
            case ARM64_INS_SQINCW:
            case ARM64_INS_SQNEG:
            case ARM64_INS_SQRDMLAH:
            case ARM64_INS_SQRDMLSH:
            case ARM64_INS_SQRDMULH:
            case ARM64_INS_SQRSHL:
            case ARM64_INS_SQRSHRN:
            case ARM64_INS_SQRSHRN2:
            case ARM64_INS_SQRSHRUN:
            case ARM64_INS_SQRSHRUN2:
            case ARM64_INS_SQSHL:
            case ARM64_INS_SQSHLU:
            case ARM64_INS_SQSHRN:
            case ARM64_INS_SQSHRN2:
            case ARM64_INS_SQSHRUN:
            case ARM64_INS_SQSHRUN2:
            case ARM64_INS_SQSUB:
            case ARM64_INS_SQXTN:
            case ARM64_INS_SQXTN2:
            case ARM64_INS_SQXTUN:
            case ARM64_INS_SQXTUN2:
            case ARM64_INS_SRHADD:
            case ARM64_INS_SRI:
            case ARM64_INS_SRSHL:
            case ARM64_INS_SRSHR:
            case ARM64_INS_SRSRA:
            case ARM64_INS_SSHL:
            case ARM64_INS_SSHLL:
            case ARM64_INS_SSHLL2:
            case ARM64_INS_SSHR:
            case ARM64_INS_SSRA:
            case ARM64_INS_SSUBL:
            case ARM64_INS_SSUBL2:
            case ARM64_INS_SSUBW:
            case ARM64_INS_SSUBW2:
            case ARM64_INS_ST1:
            case ARM64_INS_ST1B:
            case ARM64_INS_ST1D:
            case ARM64_INS_ST1H:
            case ARM64_INS_ST1W:
            case ARM64_INS_ST2:
            case ARM64_INS_ST2B:
            case ARM64_INS_ST2D:
            case ARM64_INS_ST2H:
            case ARM64_INS_ST2W:
            case ARM64_INS_ST3:
            case ARM64_INS_ST3B:
            case ARM64_INS_ST3D:
            case ARM64_INS_ST3H:
            case ARM64_INS_ST3W:
            case ARM64_INS_ST4:
            case ARM64_INS_ST4B:
            case ARM64_INS_ST4D:
            case ARM64_INS_ST4H:
            case ARM64_INS_ST4W:
            case ARM64_INS_STADD:
            case ARM64_INS_STADDB:
            case ARM64_INS_STADDH:
            case ARM64_INS_STADDL:
            case ARM64_INS_STADDLB:
            case ARM64_INS_STADDLH:
            case ARM64_INS_STCLR:
            case ARM64_INS_STCLRB:
            case ARM64_INS_STCLRH:
            case ARM64_INS_STCLRL:
            case ARM64_INS_STCLRLB:
            case ARM64_INS_STCLRLH:
            case ARM64_INS_STEOR:
            case ARM64_INS_STEORB:
            case ARM64_INS_STEORH:
            case ARM64_INS_STEORL:
            case ARM64_INS_STEORLB:
            case ARM64_INS_STEORLH:
            case ARM64_INS_STLLR:
            case ARM64_INS_STLLRB:
            case ARM64_INS_STLLRH:
            case ARM64_INS_STLR:
            case ARM64_INS_STLRB:
            case ARM64_INS_STLRH:
            case ARM64_INS_STLUR:
            case ARM64_INS_STLURB:
            case ARM64_INS_STLURH:
            case ARM64_INS_STLXP:
            case ARM64_INS_STLXR:
            case ARM64_INS_STLXRB:
            case ARM64_INS_STLXRH:
            case ARM64_INS_STNP:
            case ARM64_INS_STNT1B:
            case ARM64_INS_STNT1D:
            case ARM64_INS_STNT1H:
            case ARM64_INS_STNT1W:
            case ARM64_INS_STP:
            case ARM64_INS_STR:
            case ARM64_INS_STRB:
            case ARM64_INS_STRH:
            case ARM64_INS_STSET:
            case ARM64_INS_STSETB:
            case ARM64_INS_STSETH:
            case ARM64_INS_STSETL:
            case ARM64_INS_STSETLB:
            case ARM64_INS_STSETLH:
            case ARM64_INS_STSMAX:
            case ARM64_INS_STSMAXB:
            case ARM64_INS_STSMAXH:
            case ARM64_INS_STSMAXL:
            case ARM64_INS_STSMAXLB:
            case ARM64_INS_STSMAXLH:
            case ARM64_INS_STSMIN:
            case ARM64_INS_STSMINB:
            case ARM64_INS_STSMINH:
            case ARM64_INS_STSMINL:
            case ARM64_INS_STSMINLB:
            case ARM64_INS_STSMINLH:
            case ARM64_INS_STTR:
            case ARM64_INS_STTRB:
            case ARM64_INS_STTRH:
            case ARM64_INS_STUMAX:
            case ARM64_INS_STUMAXB:
            case ARM64_INS_STUMAXH:
            case ARM64_INS_STUMAXL:
            case ARM64_INS_STUMAXLB:
            case ARM64_INS_STUMAXLH:
            case ARM64_INS_STUMIN:
            case ARM64_INS_STUMINB:
            case ARM64_INS_STUMINH:
            case ARM64_INS_STUMINL:
            case ARM64_INS_STUMINLB:
            case ARM64_INS_STUMINLH:
            case ARM64_INS_STUR:
            case ARM64_INS_STURB:
            case ARM64_INS_STURH:
            case ARM64_INS_STXP:
            case ARM64_INS_STXR:
            case ARM64_INS_STXRB:
            case ARM64_INS_STXRH:
                access = MemoryAccessType::WRITE;
                break;
            default:
                throw std::runtime_error("Assumption vioation: instruction " + to_string(ins_id) + " accesses memory but isn't a read or store");
        }

        if (op.access & CS_AC_READ && access == MemoryAccessType::WRITE) {
            LOGW("Overriding memory access type: capstone reports that the instruction can read but we set it to a write-only access type");
        } else if (op.access & CS_AC_WRITE && access == MemoryAccessType::READ) {
            LOGW("Overriding memory access type: capstone reports that the instruction can write but we set it to a read-only access type");
        }

        LOGW("memory_access_at_pc: Returning fixed memory size of 8 bytes");
        return MemoryAccess(mem_addr, 8, access);
    } else {
        throw std::runtime_error("NYI: unknown architecture");
    }
}

std::optional<MemoryAccess>
CapstoneAnalysisResult::capstone_memory_reads(size_t ins_i, AArch64RegisterState &regs) const {
    if (auto access = capstone_memory_accesses(ins_i, regs); access && access->get_type() == MemoryAccessType::READ) {
        return *access;
    }
    return {};
}

std::optional<MemoryAccess>
CapstoneAnalysisResult::capstone_memory_write(size_t ins_i, AArch64RegisterState &regs) const {
    if (auto access = capstone_memory_accesses(ins_i, regs); access && access->get_type() == MemoryAccessType::WRITE) {
        return *access;
    }
    return {};
}

static std::pair<std::set<arm64_reg>, std::set<arm64_reg>> get_aarch64_capstone_reg_accesses(const cs_insn &insn) {
    std::set<arm64_reg> regs_read;
    std::set<arm64_reg> regs_write;

    auto &arm64 = insn.detail->arm64;
    for (uint8_t i = 0; i < insn.detail->regs_read_count; i++) {
        LOGV("%s", fmt::format("Implicit register read: {}", magic_enum::enum_name((arm64_reg)insn.detail->regs_write[i])).c_str());
    }
    for (uint8_t i = 0; i < insn.detail->regs_write_count; i++) {
        LOGV("%s", fmt::format("Implicit register write: {}", magic_enum::enum_name((arm64_reg)insn.detail->regs_write[i])).c_str());
    }
    for (uint8_t i = 0; i < arm64.op_count; i++) {
        auto &op = arm64.operands[i];
        if (op.type == ARM64_OP_REG) {
            if (op.reg == ARM64_REG_XZR || op.reg == ARM64_REG_WZR) {
                // Ignore the ARM zero register
                continue;
            }
            if (op.access & CS_AC_READ) {
                regs_read.insert(op.reg);
            }
            if (op.access & CS_AC_WRITE) {
                regs_write.insert(op.reg);
            }
        } else if (op.type == ARM64_OP_MEM) {
            LOGV("%s", fmt::format("Ignoring register that appears in memory operand: {}", magic_enum::enum_name(op.reg)).c_str());
        }
    }
    return std::make_pair<std::set<arm64_reg>, std::set<arm64_reg>>(std::move(regs_read), std::move(regs_write));
}

std::vector<MemoryRegion> CapstoneAnalysisResult::capstone_register_reads(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to get register reads for an out-of-bounds instruction");
    }

    std::vector<MemoryRegion> flat_reg_reads;
    if (analyzer_->arch == ProcessArchitecture::ARM64) {
        auto [regs_read, regs_write] = get_aarch64_capstone_reg_accesses(ins_[ins_i]);
        for (auto reg : regs_read) {
            auto reg_region = register_to_vex_region(reg);
            LOGV("%s", fmt::format("Instruction reads from register {} ({})", magic_enum::enum_name(reg), reg_region.str()).c_str());
            flat_reg_reads.emplace_back(reg_region);
        }
    } else {
        throw std::runtime_error("NYI: unsupported arch");
    }
    return flat_reg_reads;
}

std::vector<MemoryRegion> CapstoneAnalysisResult::capstone_register_writes(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to get register reads for an out-of-bounds instruction");
    }
    std::vector<MemoryRegion> flat_reg_writes;
    if (analyzer_->arch == ProcessArchitecture::ARM64) {
        auto [regs_read, regs_write] = get_aarch64_capstone_reg_accesses(ins_[ins_i]);
        for (auto reg : regs_write) {
            auto reg_region = register_to_vex_region(reg);
            LOGV("%s", fmt::format("Instruction writes to register {} ({})", magic_enum::enum_name(reg), reg_region.str()).c_str());
            flat_reg_writes.emplace_back(reg_region);
        }
    } else {
        throw std::runtime_error("NYI: unsupported arch");
    }
    return flat_reg_writes;
}

bool CapstoneAnalysisResult::could_jump(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to determine if instruction is branching for an out-of-bounds instruction");
    }
    cs_insn& ins = ins_[ins_i];
    for (int i = 0; i < ins.detail->groups_count; i++) {
        auto group = ins.detail->groups[i];
        if (group == CS_GRP_JUMP
            || group == CS_GRP_BRANCH_RELATIVE
            || group == CS_GRP_CALL
            || group == CS_GRP_RET
            || group == CS_GRP_IRET
            )
            return true;
    }
    return false;
}

bool CapstoneAnalysisResult::is_return(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to determine if instruction is branching for an out-of-bounds instruction");
    }
    cs_insn& ins = ins_[ins_i];
    for (int i = 0; i < ins.detail->groups_count; i++) {
        auto group = ins.detail->groups[i];
        if (group == CS_GRP_RET)
            return true;
    }
    return false;
}

bool CapstoneAnalysisResult::is_syscall(size_t ins_i) const {
    if (ins_i >= size()) {
        throw std::runtime_error("Tried to determine if instruction is branching for an out-of-bounds instruction");
    }
    cs_insn& ins = ins_[ins_i];
    for (int i = 0; i < ins.detail->groups_count; i++) {
        auto group = ins.detail->groups[i];
        if (group == CS_GRP_INT)
            return true;
    }
    return false;
}

IRSBResult &AnalysisResult::get_irsb() {
    return irsb_;
}

InstructionAnalyzer::InstructionAnalyzer(ProcessArchitecture proc_arch) : arch(proc_arch) {
    cs_arch arch;
    cs_mode mode;
    switch (proc_arch) {
        case ProcessArchitecture::ARM:
            arch = CS_ARCH_ARM;
            throw std::runtime_error("NYI: detect thumb mode and set mode accordingly");
            break;
        case ProcessArchitecture::ARM64:
            arch = CS_ARCH_ARM64;
            // TODO: Is it reasonable to assume little-endianness on ARM: https://stackoverflow.com/a/28726501
            mode = CS_MODE_ARM;
            break;
        case ProcessArchitecture::UNKNOWN:
            throw std::runtime_error("No processing architecture specified");
    }

    if (cs_open(arch, mode, &_handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone handle");
    }
    // Enable detail option to classify instruction in semantic groups (e.g. whether an instruction branches)
    if (cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        throw std::runtime_error("Failed to enable detail option");
    }
}

InstructionAnalyzer::~InstructionAnalyzer() {
    if (cs_close(&_handle) != CS_ERR_OK) {
        LOGE("Failed to close Capstone handle");
    }
}

InstructionAnalyzer &InstructionAnalyzer::get_instance() {
    static InstructionAnalyzer instance(ProcessArchitecture::ARM64);
    return instance;
}

AnalysisResult InstructionAnalyzer::analyze(const uint8_t *code, size_t size, uint64_t ip) {
    cs_insn *insn;
    size_t count = cs_disasm(_handle, code, size, ip, 0, &insn);
    if (count <= 0) {
        throw std::runtime_error(
                fmt::format("Capstone disassembly failed: {}", magic_enum::enum_name(cs_errno(_handle)))
        );
    }
    auto vex_anal = VEXLifter::get_instance().analyze(code, size, ip);
    return AnalysisResult(this, insn, count, std::move(vex_anal));
}

CapstoneAnalysisResult
InstructionAnalyzer::analyze_capstone(const uint8_t *code, size_t size, uint64_t ip) {
    cs_insn *insn;
    size_t count = cs_disasm(_handle, code, size, ip, 0, &insn);
    if (count <= 0) {
        throw std::runtime_error(
                fmt::format("Capstone disassembly failed: {}", magic_enum::enum_name(cs_errno(_handle)))
        );
    }
    return CapstoneAnalysisResult(this, insn, count);
}

CapstoneAnalysisResult::CapstoneAnalysisResult(InstructionAnalyzer *analyzer, cs_insn *ins,
                                               size_t count) : analyzer_(analyzer), ins_(ins),
                                                               count_(count) {
    if (count_ == 0 || !ins_)
        throw std::runtime_error("No instructions analyzed");
}

CapstoneAnalysisResult::CapstoneAnalysisResult(CapstoneAnalysisResult &&other)
    : analyzer_(other.analyzer_)
    , ins_(other.ins_)
    , count_(other.count_) {
    other.ins_ = nullptr;
}

CapstoneAnalysisResult::~CapstoneAnalysisResult() {
    if (ins_)
        cs_free(ins_, count_);
}
