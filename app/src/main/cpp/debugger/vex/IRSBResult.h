#pragma once

#include <vector>
#include <debugger/taint/AnnotatedAddressSpace.h>
class VEXLifter;

extern "C" {
#include <libvex.h>
}

enum class AccessTarget {
    Register,
    Memory
};

enum class AccessType {
    Read,
    Write
};

struct GuestAccess {
    GuestAccess(const MemoryRegion &region, AccessTarget target, AccessType type);

    MemoryRegion region;
    AccessTarget target;
    AccessType type;

    bool operator==(const GuestAccess &rhs) const;

    bool operator!=(const GuestAccess &rhs) const;

    std::string str() const;
};

/**
 * Memory or register reads that influences the value of a memory or register write
 */
struct GuestModification {
    std::vector<GuestAccess> reads;
    GuestAccess write;
};

/**
 * Modification to the guest state as a result of a single instruction, consisting of one or more
 * IRStmts
 */
struct GuestModifications {
    std::vector<GuestModification> rw_pairs;
    /**
     * Memory or register reads that have not influenced any written values
     * Example instruction that contains unused reads: ldr wzr, [x21]
     * ------ IMark(0x712B4F90, 4, 0) ------
     * t3 = GET:I64(184)
     * t2 = Add64(t3,0x0:I64)
     * t5 = LDle:I32(t2)
     * t4 = 32Uto64(t5)                      // Never written anywhere
     * PUT(272) = 0x712B4F94:I64
     * t6 = GET:I64(272)
     * PUT(272) = t6; exit-Boring
     */
    std::vector<GuestAccess> unused_reads;

    void for_each_mem_access(std::function<void(const GuestAccess&)> cb);
};

/**
 * Jump locations at the end of a basic block
 */
class BasicBlockJump {
public:
    virtual ~BasicBlockJump() = default;
    /**
     * True if the target jump address can be determined statically
     */
    virtual bool is_static_target() = 0;

    virtual uint64_t get_target() = 0;
};

/**
 * Jump location that can be determined statically
 */
class BasicBlockStaticJump : public BasicBlockJump {
private:
    uint64_t target_;
public:
    BasicBlockStaticJump(uint64_t target);

    bool is_static_target() override;

    uint64_t get_target() override;
};

/**
 * Non-static jump location
 */
class BasicBlockDynamicJump : public BasicBlockJump {
public:
    bool is_static_target() override;

    uint64_t get_target() override;
};


enum class LLSC_Kind {
    CLEAR_EXCLUSIVE,
    LOAD_LINKED,
    STORE_CONDITIONAL
};

class IRSBResult {
private:
    IRSB *irsb_;
    /**
     * Unique ID to check validity of irsb_
     */
    size_t irsb_id_;

    /**
     * Array of instructions that were analyzed for this IRBS
     */
    std::vector<uint32_t> machine_instructions_;

    /**
     * Index of first IRSB statement of the i-th instruction
     */
    std::vector<size_t> first_irstmt_;

    /**
     * Maps temporary (indexed starting from 0) to its SSA assignment statement
     */
    std::vector<std::optional<size_t>> temp_assign_;
    /**
     * Number of translated machine instructions
     */
    size_t ins_count_;
    /**
     * Maps instruction to LLSC type, overriding the translated IR.
     * Useful when the IRSB contains instructions that weren't able to be decoded
     */
    std::map<size_t, LLSC_Kind> llsc_overrides_;

    void validate_ins_i(size_t ins_i);

    /**
     * Validate irsb_ to make sure it's still alive, and return a pointer to it
     */
    IRSB *get_irsb();

    /**
     * Return the statement index after an IMark of the ins_i-th instruction relative to the IRSB
     */
    size_t get_first_stmt_at_instruction(size_t ins_i);

    size_t get_assigning_statement(size_t temp_id);

    std::vector<GuestAccess> get_guest_accesses_for_temp(size_t temp_id, std::function<uint64_t(Int)> get_register_value, std::function<void(size_t)> on_stmt_visit);

    std::vector<GuestAccess>
    get_guest_accesses(IRExpr *expr, std::function<uint64_t(Int)> get_register_value, std::function<void(size_t)> on_stmt_visit);

    IRSBResult(IRSB *irsb, std::vector<uint32_t> machine_instructions, size_t irsb_id);
public:
    friend VEXLifter;
    /*
     * Return the number of translated machine instructions of the provided IRSB
     */
    size_t get_ins_count();

    uint64_t get_instruction_address(size_t ins_i);

    /**
     * Evaluate a VEX IR expression using values obtained from the guest environment
     * @param expr Expression to evaluate
     * @param get_register_value Function that returns the register value of the guest state for the
     * provided register
     * @return Evaluated value
     */
    uint64_t eval_expr(IRExpr *expr, std::function<uint64_t(Int)>get_register_value);

    /**
     * For every register or memory write, collect all memory or register reads of any transitive
     * operands of the instruction that leads to the write
     * @param ins_i Instruction number relative to IRSB start
     * @param get_register_value Lambda that accepts a vex offset of a register and returns the
     * corresponding value of the register of the stopped process
     */
    GuestModifications get_guest_modifications(size_t ins_i, std::function<uint64_t(Int)> get_register_value);

    IRJumpKind get_jump_kind();

    /**
     * Returns whether the given instruction is a load-linked, store-conditional, or neither of the
     * two
     * @param ins_i Instruction index of this IRSB
     */
    std::optional<LLSC_Kind> get_llsc_kind(size_t ins_i);

    bool has_llsc_override(size_t ins_i);
    void override_llsc_kind(size_t ins_i, LLSC_Kind kind);

    /**
     * Get a list of all static and dynamic jump locations at the end of the basic block
     */
    std::vector<std::unique_ptr<BasicBlockJump>> get_jump_targets();

    /**
     * Print all lifted IR statements
     */
    void print_IRSB();

    /**
     * Pretty print IRStmts of a machine instruction
     * @param ins_i Machine instruction index
     */
    void print_ins_IRStmts(size_t ins_i);
};
