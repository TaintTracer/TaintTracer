#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include "aarch64.h"
#include <android/logging.h>
#include <libvex_guest_offsets.h>
#include <string>
#include <fmt/format.h>
#include <debugger/Process.h>
#include <debugger/Syscall.h>
#include <debugger/files/FileDescriptorTable.h>
#include <debugger/binder/BinderDriver.h>
#include <linux/android/binder.h>
#include <linux/futex.h>
#include <sys/time.h>

const user_pt_regs& AArch64RegisterState::get_gp_registers() {
    if (!gpregs_) {
        user_pt_regs regs;
        struct iovec io {
                .iov_base = &regs,
                .iov_len = sizeof(regs)
        };
        TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid_, NT_PRSTATUS, &io));
        gpregs_.emplace(regs);
    }
    return gpregs_.value();
}

void AArch64RegisterState::set_gp_registers(const user_pt_regs &regs) {
    gpregs_.reset();
    auto io = iovec {
        .iov_base = (void *) &regs,
        .iov_len = sizeof(regs)
    };
    TRYSYSFATAL(ptrace(PTRACE_SETREGSET, pid_, NT_PRSTATUS, &io));
}

void AArch64RegisterState::set_syscall(int syscall_number) {
    auto io = iovec {
            .iov_base = (void *) &syscall_number,
            .iov_len = sizeof(syscall_number)
    };
    TRYSYSFATAL(ptrace(PTRACE_SETREGSET, pid_, NT_ARM_SYSTEM_CALL, &io));
}

const user_fpsimd_state& AArch64RegisterState::get_simd_registers() {
    if (!simdregs_) {
        user_fpsimd_state regs;
        struct iovec io {
                .iov_base = &regs,
                .iov_len = sizeof(regs)
        };
        TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid_, NT_PRFPREG, &io));
        simdregs_.emplace(regs);
    }
    return simdregs_.value();
}

uint64_t AArch64RegisterState::get_pc() {
    return get_gp_registers().pc;
}

uint64_t AArch64RegisterState::get_sp() {
    return get_gp_registers().sp;
}

uint64_t AArch64RegisterState::operator[](arm64_reg reg) {
    switch (reg) {
        /* GP regs */
        case ARM64_REG_X0:
            return get_gp_registers().regs[0];
        case ARM64_REG_X1:
            return get_gp_registers().regs[1];
        case ARM64_REG_X2:
            return get_gp_registers().regs[2];
        case ARM64_REG_X3:
            return get_gp_registers().regs[3];
        case ARM64_REG_X4:
            return get_gp_registers().regs[4];
        case ARM64_REG_X5:
            return get_gp_registers().regs[5];
        case ARM64_REG_X6:
            return get_gp_registers().regs[6];
        case ARM64_REG_X7:
            return get_gp_registers().regs[7];
        case ARM64_REG_X8:
            return get_gp_registers().regs[8];
        case ARM64_REG_X9:
            return get_gp_registers().regs[9];
        case ARM64_REG_X10:
            return get_gp_registers().regs[10];
        case ARM64_REG_X11:
            return get_gp_registers().regs[11];
        case ARM64_REG_X12:
            return get_gp_registers().regs[12];
        case ARM64_REG_X13:
            return get_gp_registers().regs[13];
        case ARM64_REG_X14:
            return get_gp_registers().regs[14];
        case ARM64_REG_X15:
            return get_gp_registers().regs[15];
        case ARM64_REG_X16:
            return get_gp_registers().regs[16];
        case ARM64_REG_X17:
            return get_gp_registers().regs[17];
        case ARM64_REG_X18:
            return get_gp_registers().regs[18];
        case ARM64_REG_X19:
            return get_gp_registers().regs[19];
        case ARM64_REG_X20:
            return get_gp_registers().regs[20];
        case ARM64_REG_X21:
            return get_gp_registers().regs[21];
        case ARM64_REG_X22:
            return get_gp_registers().regs[22];
        case ARM64_REG_X23:
            return get_gp_registers().regs[23];
        case ARM64_REG_X24:
            return get_gp_registers().regs[24];
        case ARM64_REG_X25:
            return get_gp_registers().regs[25];
        case ARM64_REG_X26:
            return get_gp_registers().regs[26];
        case ARM64_REG_X27:
            return get_gp_registers().regs[27];
        case ARM64_REG_X28:
            return get_gp_registers().regs[28];
        case ARM64_REG_X29:
            return get_gp_registers().regs[29];
        case ARM64_REG_X30:
            return get_gp_registers().regs[30];
        case ARM64_REG_SP:
            return get_gp_registers().sp;
        /* SIMD regs */
        // cat arm64.h | perl -ne '/ARM64_REG_Q(\d+),/ && print "case ARM64_REG_Q".$1.":\ncase ARM64_REG_V".$1.":\nreturn get_simd_registers().vregs[".$1."];\n"'
        default:
            throw std::runtime_error("NYI: non-whole or SIMD reg");
            throw std::runtime_error("NYI: reading non-whole registers");
    }
}

uint64_t AArch64RegisterState::read_from_vex_offset(Int offset) {
    switch (offset) {
        case OFFSET_arm64_X0:
            return get_gp_registers().regs[0];
        case OFFSET_arm64_X1:
            return get_gp_registers().regs[1];
        case OFFSET_arm64_X2:
            return get_gp_registers().regs[2];
        case OFFSET_arm64_X3:
            return get_gp_registers().regs[3];
        case OFFSET_arm64_X4:
            return get_gp_registers().regs[4];
        case OFFSET_arm64_X5:
            return get_gp_registers().regs[5];
        case OFFSET_arm64_X6:
            return get_gp_registers().regs[6];
        case OFFSET_arm64_X7:
            return get_gp_registers().regs[7];
        case OFFSET_arm64_X8:
            return get_gp_registers().regs[8];
        case OFFSET_arm64_X9:
            return get_gp_registers().regs[9];
        case OFFSET_arm64_X10:
            return get_gp_registers().regs[10];
        case OFFSET_arm64_X11:
            return get_gp_registers().regs[11];
        case OFFSET_arm64_X12:
            return get_gp_registers().regs[12];
        case OFFSET_arm64_X13:
            return get_gp_registers().regs[13];
        case OFFSET_arm64_X14:
            return get_gp_registers().regs[14];
        case OFFSET_arm64_X15:
            return get_gp_registers().regs[15];
        case OFFSET_arm64_X16:
            return get_gp_registers().regs[16];
        case OFFSET_arm64_X17:
            return get_gp_registers().regs[17];
        case OFFSET_arm64_X18:
            return get_gp_registers().regs[18];
        case OFFSET_arm64_X19:
            return get_gp_registers().regs[19];
        case OFFSET_arm64_X20:
            return get_gp_registers().regs[20];
        case OFFSET_arm64_X21:
            return get_gp_registers().regs[21];
        case OFFSET_arm64_X22:
            return get_gp_registers().regs[22];
        case OFFSET_arm64_X23:
            return get_gp_registers().regs[23];
        case OFFSET_arm64_X24:
            return get_gp_registers().regs[24];
        case OFFSET_arm64_X25:
            return get_gp_registers().regs[25];
        case OFFSET_arm64_X26:
            return get_gp_registers().regs[26];
        case OFFSET_arm64_X27:
            return get_gp_registers().regs[27];
        case OFFSET_arm64_X28:
            return get_gp_registers().regs[28];
        case OFFSET_arm64_X29:
            return get_gp_registers().regs[29];
        case OFFSET_arm64_X30:
            return get_gp_registers().regs[30];
        case OFFSET_arm64_PC:
            return get_gp_registers().pc;
        case OFFSET_arm64_XSP:
            return get_gp_registers().sp;
        default:
            throw std::runtime_error(
                    "NYI: non-whole, SIMD, or other reg requested with offset " + std::to_string(offset));
    }
}

void AArch64RegisterState::clear() {
    gpregs_.reset();
    simdregs_.reset();
}

/**
 * Register list: https://developer.arm.com/architectures/learn-the-architecture/armv8-a-instruction-set-architecture/registers-in-aarch64-general-purpose-registers
 * The following perl script has been used to generate parts of the implementation:
 *  cat arm64.h | perl -ne '/ARM64_REG_V(\d+),/ && print "case ARM64_REG_V".$1.":\n_return MemoryRegion::from_start_and_size(OFFSET_arm64_Q".$1.", 16);\n"'
 */
MemoryRegion register_to_vex_region(arm64_reg reg) {
    switch (reg) {
        case ARM64_REG_INVALID:
        case ARM64_REG_ENDING:
            throw std::runtime_error("Invalid register provided");
        case ARM64_REG_X29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X29, 8);

        case ARM64_REG_X30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X30, 8);

        case ARM64_REG_NZCV:
            // Condition flags
            throw std::runtime_error("NYI");
        case ARM64_REG_SP:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_XSP, 8);

        case ARM64_REG_WSP:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_XSP, 4);

        case ARM64_REG_WZR:
        case ARM64_REG_XZR:
            // Zero register, see https://stackoverflow.com/a/52411101
            throw std::runtime_error("NYI");
        case ARM64_REG_B0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q0, 1);

        case ARM64_REG_B1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q1, 1);

        case ARM64_REG_B2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q2, 1);

        case ARM64_REG_B3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q3, 1);

        case ARM64_REG_B4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q4, 1);

        case ARM64_REG_B5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q5, 1);

        case ARM64_REG_B6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q6, 1);

        case ARM64_REG_B7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q7, 1);

        case ARM64_REG_B8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q8, 1);

        case ARM64_REG_B9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q9, 1);

        case ARM64_REG_B10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q10, 1);

        case ARM64_REG_B11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q11, 1);

        case ARM64_REG_B12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q12, 1);

        case ARM64_REG_B13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q13, 1);

        case ARM64_REG_B14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q14, 1);

        case ARM64_REG_B15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q15, 1);

        case ARM64_REG_B16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q16, 1);

        case ARM64_REG_B17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q17, 1);

        case ARM64_REG_B18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q18, 1);

        case ARM64_REG_B19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q19, 1);

        case ARM64_REG_B20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q20, 1);

        case ARM64_REG_B21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q21, 1);

        case ARM64_REG_B22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q22, 1);

        case ARM64_REG_B23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q23, 1);

        case ARM64_REG_B24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q24, 1);

        case ARM64_REG_B25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q25, 1);

        case ARM64_REG_B26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q26, 1);

        case ARM64_REG_B27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q27, 1);

        case ARM64_REG_B28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q28, 1);

        case ARM64_REG_B29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q29, 1);

        case ARM64_REG_B30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q30, 1);

        case ARM64_REG_B31:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q31, 1);

        case ARM64_REG_D0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q0, 8);

        case ARM64_REG_D1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q1, 8);

        case ARM64_REG_D2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q2, 8);

        case ARM64_REG_D3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q3, 8);

        case ARM64_REG_D4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q4, 8);

        case ARM64_REG_D5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q5, 8);

        case ARM64_REG_D6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q6, 8);

        case ARM64_REG_D7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q7, 8);

        case ARM64_REG_D8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q8, 8);

        case ARM64_REG_D9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q9, 8);

        case ARM64_REG_D10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q10, 8);

        case ARM64_REG_D11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q11, 8);

        case ARM64_REG_D12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q12, 8);

        case ARM64_REG_D13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q13, 8);

        case ARM64_REG_D14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q14, 8);

        case ARM64_REG_D15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q15, 8);

        case ARM64_REG_D16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q16, 8);

        case ARM64_REG_D17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q17, 8);

        case ARM64_REG_D18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q18, 8);

        case ARM64_REG_D19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q19, 8);

        case ARM64_REG_D20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q20, 8);

        case ARM64_REG_D21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q21, 8);

        case ARM64_REG_D22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q22, 8);

        case ARM64_REG_D23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q23, 8);

        case ARM64_REG_D24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q24, 8);

        case ARM64_REG_D25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q25, 8);

        case ARM64_REG_D26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q26, 8);

        case ARM64_REG_D27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q27, 8);

        case ARM64_REG_D28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q28, 8);

        case ARM64_REG_D29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q29, 8);

        case ARM64_REG_D30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q30, 8);

        case ARM64_REG_D31:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q31, 8);

        case ARM64_REG_H0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q0, 2);

        case ARM64_REG_H1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q1, 2);

        case ARM64_REG_H2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q2, 2);

        case ARM64_REG_H3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q3, 2);

        case ARM64_REG_H4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q4, 2);

        case ARM64_REG_H5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q5, 2);

        case ARM64_REG_H6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q6, 2);

        case ARM64_REG_H7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q7, 2);

        case ARM64_REG_H8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q8, 2);

        case ARM64_REG_H9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q9, 2);

        case ARM64_REG_H10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q10, 2);

        case ARM64_REG_H11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q11, 2);

        case ARM64_REG_H12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q12, 2);

        case ARM64_REG_H13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q13, 2);

        case ARM64_REG_H14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q14, 2);

        case ARM64_REG_H15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q15, 2);

        case ARM64_REG_H16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q16, 2);

        case ARM64_REG_H17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q17, 2);

        case ARM64_REG_H18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q18, 2);

        case ARM64_REG_H19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q19, 2);

        case ARM64_REG_H20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q20, 2);

        case ARM64_REG_H21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q21, 2);

        case ARM64_REG_H22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q22, 2);

        case ARM64_REG_H23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q23, 2);

        case ARM64_REG_H24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q24, 2);

        case ARM64_REG_H25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q25, 2);

        case ARM64_REG_H26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q26, 2);

        case ARM64_REG_H27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q27, 2);

        case ARM64_REG_H28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q28, 2);

        case ARM64_REG_H29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q29, 2);

        case ARM64_REG_H30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q30, 2);

        case ARM64_REG_H31:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q31, 2);

        case ARM64_REG_Q0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q0, 16);

        case ARM64_REG_Q1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q1, 16);

        case ARM64_REG_Q2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q2, 16);

        case ARM64_REG_Q3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q3, 16);

        case ARM64_REG_Q4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q4, 16);

        case ARM64_REG_Q5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q5, 16);

        case ARM64_REG_Q6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q6, 16);

        case ARM64_REG_Q7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q7, 16);

        case ARM64_REG_Q8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q8, 16);

        case ARM64_REG_Q9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q9, 16);

        case ARM64_REG_Q10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q10, 16);

        case ARM64_REG_Q11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q11, 16);

        case ARM64_REG_Q12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q12, 16);

        case ARM64_REG_Q13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q13, 16);

        case ARM64_REG_Q14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q14, 16);

        case ARM64_REG_Q15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q15, 16);

        case ARM64_REG_Q16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q16, 16);

        case ARM64_REG_Q17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q17, 16);

        case ARM64_REG_Q18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q18, 16);

        case ARM64_REG_Q19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q19, 16);

        case ARM64_REG_Q20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q20, 16);

        case ARM64_REG_Q21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q21, 16);

        case ARM64_REG_Q22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q22, 16);

        case ARM64_REG_Q23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q23, 16);

        case ARM64_REG_Q24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q24, 16);

        case ARM64_REG_Q25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q25, 16);

        case ARM64_REG_Q26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q26, 16);

        case ARM64_REG_Q27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q27, 16);

        case ARM64_REG_Q28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q28, 16);

        case ARM64_REG_Q29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q29, 16);

        case ARM64_REG_Q30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q30, 16);

        case ARM64_REG_Q31:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q31, 16);

        case ARM64_REG_S0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q0, 4);

        case ARM64_REG_S1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q1, 4);

        case ARM64_REG_S2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q2, 4);

        case ARM64_REG_S3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q3, 4);

        case ARM64_REG_S4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q4, 4);

        case ARM64_REG_S5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q5, 4);

        case ARM64_REG_S6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q6, 4);

        case ARM64_REG_S7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q7, 4);

        case ARM64_REG_S8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q8, 4);

        case ARM64_REG_S9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q9, 4);

        case ARM64_REG_S10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q10, 4);

        case ARM64_REG_S11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q11, 4);

        case ARM64_REG_S12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q12, 4);

        case ARM64_REG_S13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q13, 4);

        case ARM64_REG_S14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q14, 4);

        case ARM64_REG_S15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q15, 4);

        case ARM64_REG_S16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q16, 4);

        case ARM64_REG_S17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q17, 4);

        case ARM64_REG_S18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q18, 4);

        case ARM64_REG_S19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q19, 4);

        case ARM64_REG_S20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q20, 4);

        case ARM64_REG_S21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q21, 4);

        case ARM64_REG_S22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q22, 4);

        case ARM64_REG_S23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q23, 4);

        case ARM64_REG_S24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q24, 4);

        case ARM64_REG_S25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q25, 4);

        case ARM64_REG_S26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q26, 4);

        case ARM64_REG_S27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q27, 4);

        case ARM64_REG_S28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q28, 4);

        case ARM64_REG_S29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q29, 4);

        case ARM64_REG_S30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q30, 4);

        case ARM64_REG_S31:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q31, 4);

        case ARM64_REG_W0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X0, 4);

        case ARM64_REG_W1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X1, 4);

        case ARM64_REG_W2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X2, 4);

        case ARM64_REG_W3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X3, 4);

        case ARM64_REG_W4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X4, 4);

        case ARM64_REG_W5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X5, 4);

        case ARM64_REG_W6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X6, 4);

        case ARM64_REG_W7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X7, 4);

        case ARM64_REG_W8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X8, 4);

        case ARM64_REG_W9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X9, 4);

        case ARM64_REG_W10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X10, 4);

        case ARM64_REG_W11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X11, 4);

        case ARM64_REG_W12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X12, 4);

        case ARM64_REG_W13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X13, 4);

        case ARM64_REG_W14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X14, 4);

        case ARM64_REG_W15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X15, 4);

        case ARM64_REG_W16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X16, 4);

        case ARM64_REG_W17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X17, 4);

        case ARM64_REG_W18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X18, 4);

        case ARM64_REG_W19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X19, 4);

        case ARM64_REG_W20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X20, 4);

        case ARM64_REG_W21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X21, 4);

        case ARM64_REG_W22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X22, 4);

        case ARM64_REG_W23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X23, 4);

        case ARM64_REG_W24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X24, 4);

        case ARM64_REG_W25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X25, 4);

        case ARM64_REG_W26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X26, 4);

        case ARM64_REG_W27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X27, 4);

        case ARM64_REG_W28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X28, 4);

        case ARM64_REG_W29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X29, 4);

        case ARM64_REG_W30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X30, 4);

        case ARM64_REG_X0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X0, 8);

        case ARM64_REG_X1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X1, 8);

        case ARM64_REG_X2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X2, 8);

        case ARM64_REG_X3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X3, 8);

        case ARM64_REG_X4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X4, 8);

        case ARM64_REG_X5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X5, 8);

        case ARM64_REG_X6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X6, 8);

        case ARM64_REG_X7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X7, 8);

        case ARM64_REG_X8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X8, 8);

        case ARM64_REG_X9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X9, 8);

        case ARM64_REG_X10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X10, 8);

        case ARM64_REG_X11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X11, 8);

        case ARM64_REG_X12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X12, 8);

        case ARM64_REG_X13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X13, 8);

        case ARM64_REG_X14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X14, 8);

        case ARM64_REG_X15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X15, 8);

        case ARM64_REG_X16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X16, 8);

        case ARM64_REG_X17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X17, 8);

        case ARM64_REG_X18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X18, 8);

        case ARM64_REG_X19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X19, 8);

        case ARM64_REG_X20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X20, 8);

        case ARM64_REG_X21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X21, 8);

        case ARM64_REG_X22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X22, 8);

        case ARM64_REG_X23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X23, 8);

        case ARM64_REG_X24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X24, 8);

        case ARM64_REG_X25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X25, 8);

        case ARM64_REG_X26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X26, 8);

        case ARM64_REG_X27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X27, 8);

        case ARM64_REG_X28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_X28, 8);

        case ARM64_REG_V0:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q0, 16);

        case ARM64_REG_V1:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q1, 16);

        case ARM64_REG_V2:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q2, 16);

        case ARM64_REG_V3:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q3, 16);

        case ARM64_REG_V4:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q4, 16);

        case ARM64_REG_V5:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q5, 16);

        case ARM64_REG_V6:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q6, 16);

        case ARM64_REG_V7:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q7, 16);

        case ARM64_REG_V8:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q8, 16);

        case ARM64_REG_V9:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q9, 16);

        case ARM64_REG_V10:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q10, 16);

        case ARM64_REG_V11:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q11, 16);

        case ARM64_REG_V12:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q12, 16);

        case ARM64_REG_V13:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q13, 16);

        case ARM64_REG_V14:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q14, 16);

        case ARM64_REG_V15:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q15, 16);

        case ARM64_REG_V16:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q16, 16);

        case ARM64_REG_V17:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q17, 16);

        case ARM64_REG_V18:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q18, 16);

        case ARM64_REG_V19:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q19, 16);

        case ARM64_REG_V20:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q20, 16);

        case ARM64_REG_V21:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q21, 16);

        case ARM64_REG_V22:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q22, 16);

        case ARM64_REG_V23:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q23, 16);

        case ARM64_REG_V24:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q24, 16);

        case ARM64_REG_V25:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q25, 16);

        case ARM64_REG_V26:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q26, 16);

        case ARM64_REG_V27:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q27, 16);

        case ARM64_REG_V28:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q28, 16);

        case ARM64_REG_V29:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q29, 16);

        case ARM64_REG_V30:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q30, 16);

        case ARM64_REG_V31:
            return MemoryRegion::from_start_and_size(OFFSET_arm64_Q31, 16);
        default:
            throw std::runtime_error(fmt::format("Unhandled register type: {}", reg));
    }
}

std::vector<arm64_reg> vex_region_to_register(MemoryRegion r) {
    assert(r.start_address != r.end_address);

    // Ordered by vex offset
    static const arm64_reg ordered_regs[] = {
            ARM64_REG_X0,
            ARM64_REG_X1,
            ARM64_REG_X2,
            ARM64_REG_X3,
            ARM64_REG_X4,
            ARM64_REG_X5,
            ARM64_REG_X6,
            ARM64_REG_X7,
            ARM64_REG_X8,
            ARM64_REG_X9,
            ARM64_REG_X10,
            ARM64_REG_X11,
            ARM64_REG_X12,
            ARM64_REG_X13,
            ARM64_REG_X14,
            ARM64_REG_X15,
            ARM64_REG_X16,
            ARM64_REG_X17,
            ARM64_REG_X18,
            ARM64_REG_X19,
            ARM64_REG_X20,
            ARM64_REG_X21,
            ARM64_REG_X22,
            ARM64_REG_X23,
            ARM64_REG_X24,
            ARM64_REG_X25,
            ARM64_REG_X26,
            ARM64_REG_X27,
            ARM64_REG_X28,
            ARM64_REG_X29,
            ARM64_REG_X30,
            ARM64_REG_SP,
            ARM64_REG_V0,
            ARM64_REG_V1,
            ARM64_REG_V2,
            ARM64_REG_V3,
            ARM64_REG_V4,
            ARM64_REG_V5,
            ARM64_REG_V6,
            ARM64_REG_V7,
            ARM64_REG_V8,
            ARM64_REG_V9,
            ARM64_REG_V10,
            ARM64_REG_V11,
            ARM64_REG_V12,
            ARM64_REG_V13,
            ARM64_REG_V14,
            ARM64_REG_V15,
            ARM64_REG_V16,
            ARM64_REG_V17,
            ARM64_REG_V18,
            ARM64_REG_V19,
            ARM64_REG_V20,
            ARM64_REG_V21,
            ARM64_REG_V22,
            ARM64_REG_V23,
            ARM64_REG_V24,
            ARM64_REG_V25,
            ARM64_REG_V26,
            ARM64_REG_V27,
            ARM64_REG_V28,
            ARM64_REG_V29,
            ARM64_REG_V30,
            ARM64_REG_V31,
    };

    struct reg_idx {
        size_t idx;
        unsigned int remainder;
    };
    auto vex_offset_to_ordered_reg_idx = [] (int offset) -> reg_idx {
        if (OFFSET_arm64_X0 <= offset && offset < OFFSET_arm64_X30 + 8) {
            auto div = std::div(offset - OFFSET_arm64_X0, 8);
            assert(div.quot <= 30);
            return {
                    .idx = static_cast<size_t>(div.quot),
                    .remainder = static_cast<unsigned int>(div.rem)
            };
        } else if (OFFSET_arm64_XSP <= offset && offset < OFFSET_arm64_XSP + 8) {
            return {
                    .idx = 31,
                    .remainder = static_cast<unsigned int>(offset - OFFSET_arm64_XSP)
            };
        } else if (OFFSET_arm64_Q0 <= offset && offset < OFFSET_arm64_Q31 + 16) {
            auto div = std::div(offset - OFFSET_arm64_Q0, 16);
            assert(div.quot <= 31);
            return {
                    .idx = static_cast<size_t>(32 + div.quot),
                    .remainder = static_cast<unsigned int>(div.rem)
            };
        } else {
            throw std::runtime_error(fmt::format("Failed to find AArch64 instruction that matches VEX offset {}", offset));
        }
    };
    auto start = vex_offset_to_ordered_reg_idx(static_cast<int>(r.start_address));
    auto end = vex_offset_to_ordered_reg_idx(static_cast<int>(r.end_address));
    assert(start.idx <= end.idx);
    auto res = std::vector<arm64_reg> {};
    res.reserve(end.idx - start.idx + 1);
    for (auto i = start.idx; i <= (end.remainder == 0 ? end.idx - 1 : end.idx); i++) {
        res.emplace_back(ordered_regs[i]);
    }

    return res;
}

/* System call register conventions are described in `man 2 syscall` */

aarch64::syscall_number AArch64RegisterState::get_syscall_number() {
    // System call number stored in x8
    return static_cast<aarch64::syscall_number>(get_gp_registers().regs[8]);
}

uint64_t (&AArch64RegisterState::get_syscall_args())[6] {
    return *((uint64_t(*)[6])(&get_gp_registers().regs[0])); // x0 - x5
}

uint64_t AArch64RegisterState::get_syscall_retval() {
    // retval2 unused: "Other architectures do not use the second return value register"
    return get_gp_registers().regs[0]; // x0
}

void set_syscall_entry_regs(user_pt_regs &regs, uint64_t number, std::initializer_list<uint64_t> args) {
    regs.regs[8] = number;
    if (args.size() > 6) {
        throw std::runtime_error("Too many arguments provided");
    }
    // Fill x0 - x5
    for (auto [i, it] = std::pair(0, args.begin()); it != args.end(); i++, it++) {
        regs.regs[i] = *it;
    }
}

std::optional<arm64_reg> aarch64::gp_reg_id_to_reg(uint32_t reg_id) {
    switch (reg_id) {
        case 0:
            return arm64_reg::ARM64_REG_X0;
        case 1:
            return arm64_reg::ARM64_REG_X1;
        case 2:
            return arm64_reg::ARM64_REG_X2;
        case 3:
            return arm64_reg::ARM64_REG_X3;
        case 4:
            return arm64_reg::ARM64_REG_X4;
        case 5:
            return arm64_reg::ARM64_REG_X5;
        case 6:
            return arm64_reg::ARM64_REG_X6;
        case 7:
            return arm64_reg::ARM64_REG_X7;
        case 8:
            return arm64_reg::ARM64_REG_X8;
        case 9:
            return arm64_reg::ARM64_REG_X9;
        case 10:
            return arm64_reg::ARM64_REG_X10;
        case 11:
            return arm64_reg::ARM64_REG_X11;
        case 12:
            return arm64_reg::ARM64_REG_X12;
        case 13:
            return arm64_reg::ARM64_REG_X13;
        case 14:
            return arm64_reg::ARM64_REG_X14;
        case 15:
            return arm64_reg::ARM64_REG_X15;
        case 16:
            return arm64_reg::ARM64_REG_X16;
        case 17:
            return arm64_reg::ARM64_REG_X17;
        case 18:
            return arm64_reg::ARM64_REG_X18;
        case 19:
            return arm64_reg::ARM64_REG_X19;
        case 20:
            return arm64_reg::ARM64_REG_X20;
        case 21:
            return arm64_reg::ARM64_REG_X21;
        case 22:
            return arm64_reg::ARM64_REG_X22;
        case 23:
            return arm64_reg::ARM64_REG_X23;
        case 24:
            return arm64_reg::ARM64_REG_X24;
        case 25:
            return arm64_reg::ARM64_REG_X25;
        case 26:
            return arm64_reg::ARM64_REG_X26;
        case 27:
            return arm64_reg::ARM64_REG_X27;
        case 28:
            return arm64_reg::ARM64_REG_X28;
        case 29:
            return arm64_reg::ARM64_REG_X29;
        case 30:
            return arm64_reg::ARM64_REG_X30;
        case 31:
            return std::nullopt; // wzr
        default:
            throw std::runtime_error("This code is unreachable. All possible register values are handled?");
    }
}

bool aarch64::is_load_linked(uint32_t instruction) {
    /**
     * ARM Architecture Reference Manual ARMv8 C6.2.103 - C6.2.106, C6.2.161 - C6.2.164
     */
    uint32_t ins_type_bits = (0b00100001 << 22);
    uint32_t ins_type_mask = (0b11111111 << 22);
    return static_cast<bool>(0 == (ins_type_mask & (instruction ^ ins_type_bits)));
}

bool aarch64::is_store_conditional(uint32_t instruction) {
    /**
     * ARM Architecture Reference Manual ARMv8 C6.2.251 - C6.2.254, C6.2.284 - C6.2.287
     */
    uint32_t ins_type_bits = (0b00100000 << 22);
    uint32_t ins_type_mask = (0b11111111 << 22);
    return static_cast<bool>(0 == (ins_type_mask & (instruction ^ ins_type_bits)));
}

bool aarch64::is_dc_zva(uint32_t instruction) {
    // ARM Architecture Reference Manual ARMv8 C6.2.69
    uint32_t dc_zva_bits = 0xD50B7420;
    uint32_t dc_zva_mask = (uint32_t) ~0x1f;
    return (0 == (dc_zva_mask & (instruction ^ dc_zva_bits)));
}

std::vector<arm64_reg> aarch64::get_llsc_transfer_registers(uint32_t instruction) {
    if (!is_load_linked(instruction) && !(is_store_conditional(instruction))) {
        throw std::runtime_error("Attempted to get llsc transfer registers for non-llsc instruction");
    }
    auto res = std::vector<arm64_reg> {};
    auto add_reg_id =  [&] (uint32_t reg_id) {
        auto reg_enum = gp_reg_id_to_reg(reg_id);
        if (reg_enum) {
            res.push_back(*reg_enum);
        }
    };

    uint32_t rt_mask = 0x1f << 0;
    add_reg_id(instruction & rt_mask);
    add_reg_id((instruction & (rt_mask << 10)) >> 10);
    return res;
}

uint32_t aarch64::set_load_linked_transfer_registers(uint32_t instruction, uint8_t rt, uint8_t rt2) {
    /**
     * We set Rt and Rt2 to the desired values
     * If Rt2 is 0b11111, then we know the instruction is not a LDXP instruction that modifies two
     * registers.
     * Note: the instructions `ldxr Rt, [Rn]` and `ldxp Rt, xzr, [Rn]` are encoded identically.
     */
    if (!is_load_linked(instruction)) {
        throw std::runtime_error(fmt::format("Provided instruction {:#x} is not a load linked instruction", instruction));
    }
    bool is_ldxp = (instruction & ((uint32_t) 1 << 21)) != 0;
    uint32_t rt_mask = 0x1f << 0; // Can encode 32 registers: x0-x30, xzr
    uint32_t rt2_mask = rt_mask << 10;
    if (rt > rt_mask || rt2 > rt_mask) {
        throw std::runtime_error("Failed to modify load-linked instruction: provided transfer register encodings are invalid");
    }
    instruction &= ~rt_mask;
    instruction |= rt;
    uint8_t rt2_orig = (uint8_t) (instruction >> 10 & rt_mask);
    if (is_ldxp) {
        assert(rt2_orig <= rt_mask);
        if (rt == rt2) {
            // Change from ldxp to ldxr if both destination registers are the same
            // since that leads to an illegal instruction trap
            instruction = instruction & (~(1 << 21));
            rt2 = 0x1f;
        }
        instruction &= ~rt2_mask;
        instruction |= rt2 << 10;
    } else {
        if (rt2_orig != rt_mask) {
            throw std::runtime_error("Invalid ldxr instruction: Rt2 is not set to xzr");
        }
    }
    return instruction;
}

std::optional<arm64_reg> aarch64::get_store_conditional_status_register(uint32_t instruction) {
    if (!is_store_conditional(instruction)) {
        throw std::runtime_error("Provided instruction is not a store-conditional instruction");
    }
    uint32_t status_reg_mask = 0x1f << 16;
    uint32_t status_reg = (0x1f) & ((status_reg_mask & instruction) >> 16);
    return gp_reg_id_to_reg(status_reg);
}

arm64_reg aarch64::get_llsc_memory_access_register(uint32_t instruction) {
    if (!is_load_linked(instruction) && !is_store_conditional(instruction)) {
        throw std::runtime_error("Provided instruction is not a load linked or store conditional instruction");
    }
    uint32_t mem_mask = 0x1f << 5;
    uint32_t mem_reg = (0x1f) & ((mem_mask & instruction) >> 5);
    auto mem_reg_enum = gp_reg_id_to_reg(mem_reg);
    return (mem_reg_enum == std::nullopt) ? arm64_reg::ARM64_REG_SP : *mem_reg_enum;
}

void aarch64::print_registers(const user_pt_regs &regs) {
    for (int i = 0; i < 30; ++i) {
        android_printf("  x%-2d 0x%016" PRIx64, i, regs.regs[i]);
        if (i % 4 == 3) {
            android_printf("\n");
        }
    }
    android_printf("\n");
    android_printf("  sp  0x%016" PRIx64 "  lr  0x%016" PRIx64 "  pc  0x%016" PRIx64 "  pst 0x%016" PRIx64 "\n", regs.sp, regs.regs[30], regs.pc, regs.pstate);
}

std::pair<std::vector<MemoryRegion>, std::vector<MemoryRegion>>
aarch64::get_syscall_memory_accesses(Process &proc, const SyscallEvent &syscall_event) {
    auto reads = std::vector<MemoryRegion> {}; // Memory reads
    auto writes = std::vector<MemoryRegion> {}; // Memory writes
    auto &args = syscall_event.args;

    // Useful syscall table: https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm64-64_bit
    switch (syscall_event.syscall_number) {
        case aarch64::syscall_number::read:
        case aarch64::syscall_number::pread64:
        case aarch64::syscall_number::recvfrom:
        {
            auto addr = args[1];
            auto len = args[2];
            if (len != 0) {
                writes.emplace_back(MemoryRegion::from_start_and_size(addr, len));
            } else {
                LOGW("Memory region referenced by system call has length of 0");
            }
            break;
        }
        case aarch64::syscall_number::write:
        case aarch64::syscall_number::pwrite64:
        case aarch64::syscall_number::sendto:
        {
            auto addr = args[1];
            auto len = args[2];
            if (len != 0) {
                reads.emplace_back(MemoryRegion::from_start_and_size(addr, len));
            } else {
                LOGW("Memory region referenced by system call has length of 0");
            }
            break;
        }
        case aarch64::syscall_number::readv:
        case aarch64::syscall_number::preadv:
        case aarch64::syscall_number::preadv2:
        {
            auto iovec_addr = args[1];
            auto iovec_count = (int) args[2];
            writes = get_iovec_ranges(proc, iovec_addr, iovec_count);
            reads.emplace_back(MemoryRegion::from_start_and_size(iovec_addr, iovec_count * sizeof(struct iovec)));
            break;
        }
        case aarch64::syscall_number::writev:
        case aarch64::syscall_number::pwritev:
        case aarch64::syscall_number::pwritev2:
        {
            auto iovec_addr = args[1];
            auto iovec_count = (int) args[2];
            reads = get_iovec_ranges(proc, iovec_addr, iovec_count);
            reads.emplace_back(MemoryRegion::from_start_and_size(iovec_addr, iovec_count * sizeof(struct iovec)));
            break;
        }
        case aarch64::syscall_number::openat:
        {
            auto dfid = (int) args[0];
            auto filename_ptr = args[1];
            // TODO: Conservative, is the entire PATH_MAX string loaded from userspace?
            //       If not, be more accurate by reading src of __strncpy_from_user.
            reads.emplace_back(MemoryRegion::from_start_and_size(filename_ptr, PATH_MAX));
            break;
        }
        case aarch64::syscall_number::ioctl:
        {
            int fd = (int)args[0];
            uint64_t ioctl_cmd = syscall_event.args[1];
            if (proc.get_fds().is_binder_fd(fd) && ioctl_cmd == BINDER_WRITE_READ) {
                uint64_t bwr_tracee_ptr = syscall_event.args[2];
                auto bwr_mem = proc.read_memory(bwr_tracee_ptr, sizeof(binder_write_read));
                struct binder_write_read *bwr = (binder_write_read *) bwr_mem.data();
                // Meta-struct pointing to read and write buffer gets read by the kernel
                reads.emplace_back(MemoryRegion::from_start_and_size(bwr_tracee_ptr, sizeof(struct binder_write_read)));
                {
                    // It could be the case that only a few messages are processed by the driver.
                    // We are conservative in the regions of memory read.
                    uint64_t ptr = bwr->write_buffer + bwr->write_consumed;
                    uint64_t end = bwr->write_buffer + bwr->write_size;
                    assert(ptr <= end);
                    if (ptr < end) {
                        reads.emplace_back(MemoryRegion(ptr, end));
                    }
                    while (ptr < end) {
                        auto command_mem = proc.read_memory(ptr, sizeof(uint32_t));
                        auto cmd = (const binder_driver_command_protocol) *(uint32_t*) command_mem.data();
                        ptr += sizeof(uint32_t);
                        assert (ptr <= end);
                        if (cmd == BC_TRANSACTION) {
                            auto tx_mem = proc.read_memory(ptr, sizeof(binder_transaction_data));
                            auto tx = (binder_transaction_data *) tx_mem.data();
                            if (tx->data_size) {
                                reads.emplace_back(MemoryRegion::from_start_and_size(tx->data.ptr.buffer, tx->data_size));
                            }
                            if (tx->offsets_size) {
                                reads.emplace_back(MemoryRegion::from_start_and_size(tx->data.ptr.offsets, tx->offsets_size));
                            }
                        } else if (cmd == BC_TRANSACTION_SG) {
                            throw std::runtime_error("NYI: Binder scatter-gather command");
                        }
                        // Skip past command payload
                        ptr += payload_size(cmd);
                    }
                }
                // TODO: Binder recv (writes to mem)
            }
            break;
        }
        case aarch64::syscall_number::futex:
        {
            auto futex_op = (int) args[1];
            auto uaddr = args[0];
            auto timeout = args[3];
            auto uaddr2 = args[4];

            reads.emplace_back(MemoryRegion::from_start_and_size(uaddr, 4)); // Futexes are 32-bit on all platforms
            switch (futex_op & FUTEX_PRIVATE_FLAG - 1) { // Ignore flags
                case FUTEX_WAKE:
                case FUTEX_WAKE_BITSET:
                case FUTEX_FD:
                    break;
                case FUTEX_LOCK_PI:
                    writes.emplace_back(MemoryRegion::from_start_and_size(uaddr, 4));
                    if (timeout) {
                        reads.emplace_back(MemoryRegion::from_start_and_size(timeout, sizeof(struct timespec)));
                    }
                    break;
                case FUTEX_TRYLOCK_PI:
                case FUTEX_UNLOCK_PI:
                    writes.emplace_back(MemoryRegion::from_start_and_size(uaddr, 4));
                    break;
                case FUTEX_WAIT:
                case FUTEX_WAIT_BITSET:
                case FUTEX_WAIT_REQUEUE_PI:
                    if (timeout) {
                        reads.emplace_back(MemoryRegion::from_start_and_size(timeout, sizeof(struct timespec)));
                    }
                    break;
                case FUTEX_REQUEUE:
                case FUTEX_CMP_REQUEUE:
                case FUTEX_CMP_REQUEUE_PI:
                    reads.emplace_back(MemoryRegion::from_start_and_size(uaddr2, 4));
                    break;
                case FUTEX_WAKE_OP:
                    reads.emplace_back(MemoryRegion::from_start_and_size(uaddr2, 4));
                    writes.emplace_back(MemoryRegion::from_start_and_size(uaddr2, 4));
                default:
                    throw std::runtime_error(fmt::format("Unable to determine accessed memory regions for futex(): unknown futex_op {:x}", futex_op));
            }
            break;
        }
        default:
            LOGW("Ignoring system call memory accesses");
    }
    return std::make_pair(std::move(reads), std::move(writes));
}
