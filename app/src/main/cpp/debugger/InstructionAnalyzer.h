#pragma once

class AnalysisResult;
class CapstoneAnalysisResult;
class InstructionAnalyzer;
enum class ProcessArchitecture;
#include "arch/aarch64.h"
#include "Process.h"
#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include <optional>
#include <vector>

enum class MemoryAccessType {
    READ,
    WRITE
};

class MemoryAccess : public MemoryRegion {
private:
    MemoryAccessType type_;
public:
    MemoryAccess(uint64_t address, uint64_t size, MemoryAccessType type)
            : MemoryRegion(address, address + size)
            , type_(type) {}

    MemoryAccessType get_type() const {
        return type_;
    }
};

class CapstoneAnalysisResult {
    InstructionAnalyzer *analyzer_;
    cs_insn *ins_;
    size_t count_;
public:
    CapstoneAnalysisResult(InstructionAnalyzer *analyzer, cs_insn *ins, size_t count);
    CapstoneAnalysisResult(const CapstoneAnalysisResult&) = delete;
    CapstoneAnalysisResult(CapstoneAnalysisResult &&other);
    CapstoneAnalysisResult& operator=(CapstoneAnalysisResult&& rhs);
    ~CapstoneAnalysisResult();

    std::pair<unsigned char *, size_t> get_machine_bytes(size_t ins_i) const;
    std::string to_string(size_t ins_i) const;
    void print_instruction(size_t ins_i) const;
    void print_instructions() const;
    uint64_t instruction_address(size_t ins_i) const;
    bool is_memory_access(size_t ins_i) const;
    bool is_breakpoint(size_t ins_i) const;
    /**
     * Determine if the instruction could jump outside of the current basic block
     */
    bool could_jump(size_t ins_i) const;
    bool is_return(size_t ins_i) const;
    bool is_syscall(size_t ins_i) const;

    /**
     * Return the number of disassembled instructions
     */
    inline size_t size() const {
        return count_;
    }

    std::optional<MemoryAccess> capstone_memory_accesses(size_t ins_i, AArch64RegisterState &regs) const;
    std::optional<MemoryAccess> capstone_memory_reads(size_t ins_i, AArch64RegisterState &regs) const;
    std::optional<MemoryAccess> capstone_memory_write(size_t ins_i, AArch64RegisterState &regs) const;
    std::vector<MemoryRegion> capstone_register_reads(size_t ins_i) const;
    std::vector<MemoryRegion> capstone_register_writes(size_t ins_i) const;
};

class AnalysisResult : public CapstoneAnalysisResult {
private:
    IRSBResult irsb_;
public:
    AnalysisResult(InstructionAnalyzer *analyzer, cs_insn *ins, size_t count, IRSBResult irsb);

public:
    AnalysisResult(const AnalysisResult&) = delete;
    AnalysisResult(AnalysisResult&&) = default;
    AnalysisResult& operator=(const AnalysisResult&) = delete;
    AnalysisResult& operator=(AnalysisResult&& rhs);
    friend class InstructionAnalyzer;

    IRSBResult &get_irsb();
    std::optional<GuestAccess> memory_accesses(size_t ins_i, AArch64RegisterState &regs);
};


class InstructionAnalyzer {
private:
    csh _handle;
public:
    InstructionAnalyzer(ProcessArchitecture arch);
    ~InstructionAnalyzer();
    static InstructionAnalyzer &get_instance();
    const ProcessArchitecture arch;
    /**
     * Analyze a block of instructions with capstone and VEX.
     * Note: This will invalidate previous instances of AnalysisResult
     * @param code Pointer to machine instructions
     * @param size Number of bytes to analyze
     * @param ip Virtual address of the instructions
     */
    AnalysisResult analyze(const uint8_t *code, size_t size, uint64_t ip);
    CapstoneAnalysisResult analyze_capstone(const uint8_t *code, size_t size, uint64_t ip);
    friend class CapstoneAnalysisResult;
};

