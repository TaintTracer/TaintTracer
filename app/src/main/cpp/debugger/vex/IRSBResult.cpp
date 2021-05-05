#include "IRSBResult.h"
#include <string>
#include <fmt/format.h>
#include <libs/vex/pub/libvex_ir.h>
#include <android/logging.h>
#include <magic_enum.hpp>
#include <inttypes.h>
#include <debugger/arch/aarch64.h>
#include "VEXLifter.h"

GuestAccess::GuestAccess(const MemoryRegion &region, AccessTarget target, AccessType type) : region(
        region), target(target), type(type) {}

std::string GuestAccess::str() const {
    return fmt::format("{} {} at ({})", magic_enum::enum_name(type), magic_enum::enum_name(target), region.str());
}

bool GuestAccess::operator==(const GuestAccess &rhs) const {
    return region == rhs.region &&
           target == rhs.target &&
           type == rhs.type;
}

bool GuestAccess::operator!=(const GuestAccess &rhs) const {
    return !(rhs == *this);
}

void GuestModifications::for_each_mem_access(std::function<void(const GuestAccess&)> cb) {
    for (const auto &m : rw_pairs) {
        if (m.write.target == AccessTarget::Memory) {
            cb(m.write);
        }
        for (const auto &r : m.reads) {
            if (r.target == AccessTarget::Memory) {
                cb(r);
            }
        }
    }
    for (const auto &r : unused_reads) {
        if (r.target == AccessTarget::Memory) {
            cb(r);
        }
    }
}

IRSBResult::IRSBResult(IRSB *irsb, std::vector<uint32_t> machine_instructions, size_t irsb_id)
        : irsb_(irsb), machine_instructions_(std::move(machine_instructions)), irsb_id_(irsb_id), ins_count_(0) {
    size_t tmp_n = static_cast<size_t>(irsb->tyenv->types_used);
    temp_assign_.resize(tmp_n, std::nullopt);
    for (size_t i = 0; i < irsb->stmts_used; i++) {
        auto stmt = irsb->stmts[i];
        if (stmt->tag == Ist_IMark) {
            first_irstmt_.emplace_back(i + 1);
            if (i + 1 >= irsb->stmts_used) {
                throw std::runtime_error("No statements found after IMark");
            } else if (irsb->stmts[i+1]->tag == Ist_IMark) {
                throw std::runtime_error("No instructions found between IMark statements");
            }
            ins_count_++;
            assert(first_irstmt_.size() == ins_count_);
        } else if (stmt->tag == Ist_WrTmp) {
            auto &wrtmp = stmt->Ist.WrTmp;
            assert(wrtmp.tmp < tmp_n);
            temp_assign_[wrtmp.tmp] = i;
        } else if (stmt->tag == Ist_LLSC) {
            auto &llsc = stmt->Ist.LLSC;
            /*
             * Handle Load-Linked instructions: t1 = LDle-Linked(t0)
             * and Store-Conditional instructions: t1 = ( STle-Cond(t0) = t2 )
             */
            temp_assign_[llsc.result /* t1 */] = i;
        } else if (stmt->tag  == Ist_Dirty) {
            auto *dirty = stmt->Ist.Dirty.details;
            if (dirty->nFxState > 0) {
                throw std::runtime_error("NYI: dirty guest modifications e.g. register writes without PUT IRStmt");
            }
            if (dirty->tmp != IRTemp_INVALID) {
                temp_assign_[dirty->tmp] = i;
            }
        }
    }
    assert(machine_instructions_.size() >= ins_count_);
}

IRSB *IRSBResult::get_irsb() {
    if (VEXLifter::get_irsb_id_alive() != irsb_id_) {
        throw std::runtime_error("This IRSBResult instance is no longer valid");
    }
    return irsb_;
}

uint64_t IRSBResult::get_instruction_address(size_t ins_i) {
    auto *irsb = get_irsb();
    auto idx = get_first_stmt_at_instruction(ins_i) - 1;
    if (idx < 0 || irsb->stmts[idx]->tag != Ist_IMark) {
        throw std::runtime_error("Unable to compute instruction address: invalid index or not an IMark");
    }
    return irsb->stmts[idx]->Ist.IMark.addr;
}

size_t IRSBResult::get_first_stmt_at_instruction(size_t ins_i) {
    validate_ins_i(ins_i);
    return first_irstmt_[ins_i];
}

size_t IRSBResult::get_assigning_statement(size_t temp_id) {
    if (temp_id >= temp_assign_.size()) {
        throw std::runtime_error(fmt::format("Temporary t{} out of bounds", temp_id));
    }
    return temp_assign_[temp_id].value(); // Statement that assigns a value to the provided temporary
}

std::vector<GuestAccess> IRSBResult::get_guest_accesses_for_temp(size_t temp_id, std::function<uint64_t(Int)> get_register_value, std::function<void(size_t)> on_stmt_visit) {
    auto stmt_i = get_assigning_statement(temp_id);
    on_stmt_visit(stmt_i);
    auto *stmt = get_irsb()->stmts[stmt_i];
    switch (stmt->tag) {
        case Ist_WrTmp:
            assert(stmt->Ist.WrTmp.tmp == temp_id);
            return get_guest_accesses(stmt->Ist.WrTmp.data, get_register_value, on_stmt_visit);
        case Ist_LLSC:
        {
            auto &llsc = stmt->Ist.LLSC;
            assert(llsc.result == temp_id);
            if (llsc.storedata == nullptr) {
                // Treat load linked as regular memory load
                auto fake_read = IRExpr {
                    .tag = Iex_Load,
                    .Iex.Load = {
                            .addr = llsc.addr,
                            .end = llsc.end,
                            .ty = typeOfIRTemp(get_irsb()->tyenv, llsc.result)
                    }
                };
                return get_guest_accesses(&fake_read, get_register_value, on_stmt_visit);
            } else {
                // Result of store-conditional is a single bit indicating whether or not the store
                // was successful. The value is non-deterministic.
                return {};
            }
        }
        case Ist_Dirty:
        {
            auto &dirty = stmt->Ist.Dirty;

            if (strcmp(dirty.details->cee->name, "arm64g_dirtyhelper_MRS_CNTVCT_EL0") == 0) {
                assert(temp_id == dirty.details->tmp);
                return {}; // Returns clock cycle count
            } else {
                throw std::runtime_error(fmt::format("Unsupported dirty callee {}", dirty.details->cee->name));
            }
        }
            break;
        default:
            throw std::runtime_error(fmt::format("Can't get assigned temporary expression for tag {}", stmt->tag));
    }
}

uint64_t IRSBResult::eval_expr(IRExpr *expr, std::function<uint64_t(Int)> get_register_value) {
    auto irsb = get_irsb();
    /* We're currently only interested in evaluating 64-bit addresses of memory operands */
    switch (expr->tag) {
        case Iex_Binder:
            throw std::runtime_error("Binder is supposed to be internal to VEX");
        case Iex_Get:
        {
            auto &e = expr->Iex.Get;
            if (e.ty != Ity_I64) {
                throw std::runtime_error(fmt::format("Unexpected type for Get expr: {}", e.ty));
            }
            return get_register_value(e.offset);
        }
        case Iex_GetI:
            throw std::runtime_error("NYI: Expression evaluation of GetI expression");
        case Iex_RdTmp:
        {
            auto &e = expr->Iex.RdTmp;
            auto type = irsb->tyenv->types[e.tmp];
            if (type != Ity_I64 && type != Ity_I32) {
                throw std::runtime_error(fmt::format("Unexpected type for RdTmp expr: {}", type));
            }
            auto temp_id = e.tmp;
            auto *stmt = irsb->stmts[get_assigning_statement(e.tmp)]; // Statement that assigns a value to the provided temporary
            if (stmt->tag == Ist_WrTmp) {
                assert(stmt->Ist.WrTmp.tmp == temp_id);
                return eval_expr(stmt->Ist.WrTmp.data, get_register_value);
            } else {
                throw std::runtime_error("NYI: evaluate expression of temporary that wasn't assigned with WrTmp");
            }
        }
        case Iex_Binop:
        {
            auto &e = expr->Iex.Binop;
            auto op1 = eval_expr(e.arg1, get_register_value);
            auto op2 = eval_expr(e.arg2, get_register_value);
            switch (e.op) {
                case Iop_Add8:
                case Iop_Add16:
                case Iop_Add32:
                case Iop_Add64:
                    return op1 + op2;
                case Iop_Sub8:
                case Iop_Sub16:
                case Iop_Sub32:
                case Iop_Sub64:
                    return op1 - op2;
                case Iop_Mul8:
                case Iop_Mul16:
                case Iop_Mul32:
                case Iop_Mul64:
                    return op1 * op2;
                case Iop_Or8:
                case Iop_Or16:
                case Iop_Or32:
                case Iop_Or64:
                    return op1 | op2;
                case Iop_And8:
                case Iop_And16:
                case Iop_And32:
                case Iop_And64:
                    return op1 & op2;
                case Iop_Xor8:
                case Iop_Xor16:
                case Iop_Xor32:
                case Iop_Xor64:
                    return op1 ^ op2;
                case Iop_Shl8:
                case Iop_Shl16:
                case Iop_Shl32:
                case Iop_Shl64:
                    return op1 << op2;
                case Iop_Shr8:
                case Iop_Shr16:
                case Iop_Shr32:
                case Iop_Shr64:
                    return op1 >> op2;
                default:
                    throw std::runtime_error("NYI: Binop type " + std::to_string(e.op));
            }
        }
        case Iex_Const:
        {
            auto &con = expr->Iex.Const.con;
            switch (con->tag) {
                case Ico_U1:
                    return con->Ico.U1;
                case Ico_U8:
                    return con->Ico.U8;
                case Ico_U16:
                    return con->Ico.U16;
                case Ico_U32:
                    return con->Ico.U32;
                case Ico_U64:
                    return con->Ico.U64;
                case Ico_F32:
                case Ico_F32i:
                case Ico_F64:
                case Ico_F64i:
                case Ico_V128:
                case Ico_V256:
                default:
                    throw std::runtime_error(fmt::format("Unexpected const type: {}", con->tag));
            }
        }
        case Iex_Unop:
        {
            auto &e = expr->Iex.Unop;
            switch (e.op) {
                case Iop_32Uto64:
                    return (uint32_t) eval_expr(e.arg, get_register_value);
                case Iop_64to32:
                    return (uint32_t) eval_expr(e.arg, get_register_value);
                case Iop_32Sto64:
                    return (int32_t) eval_expr(e.arg, get_register_value);
                default:
                    print_IRSB(); android_printf("Failing expression: "); ppIRExpr(expr); android_printf("\n");
                    throw std::runtime_error(fmt::format("NYI: Unary expression evaluation with op {:x}", e.op));
            }
        }
        case Iex_Qop:
        case Iex_Triop:
        case Iex_Load:
        case Iex_ITE:
        case Iex_CCall:
        case Iex_VECRET:
        case Iex_GSPTR:
        default:
            print_IRSB();
            LOGE("Failing expr: ");
            ppIRExpr(expr); android_printf("\n");
            throw std::runtime_error(fmt::format("NYI: Expression evaluation of type {:x}", expr->tag));
    }
}

/**
 * Place all unique elements in front of the collection.
 * Useful for removing duplicates when element type does not implement operator<
 * Note: has a complexity of O(n^2)
 * @param begin Start of elements to filter
 * @param end End of the elements to filter
 * @return Start of the unfiltered region at the tail of the collection
 */
template <typename ForwardIterator>
ForwardIterator filter_duplicates_inplace(ForwardIterator begin, ForwardIterator end)
{
    auto unfiltered_begin = begin;
    for (auto it = begin; it != end; it++) {
        if (std::find(begin, unfiltered_begin, *it) == unfiltered_begin ) {
            if (unfiltered_begin != it ) {
                *unfiltered_begin = *it;
            }
            unfiltered_begin++;
        }
    }

    return unfiltered_begin;
}

std::vector<GuestAccess> IRSBResult::get_guest_accesses(IRExpr *expr, std::function<uint64_t(Int)> get_register_value, std::function<void(size_t)> on_stmt_visit) {
    switch (expr->tag) {
        case Iex_Binder:
            throw std::runtime_error("Binder is supposed to be internal to VEX");
        case Iex_Get:
        {
            auto &e = expr->Iex.Get;
            return {
                GuestAccess{
                     MemoryRegion::from_start_and_size_signed(e.offset, sizeofIRType(e.ty)),
                     AccessTarget::Register,
                     AccessType::Read
                }
            };
        }
        case Iex_GetI:
            throw std::runtime_error("NYI: Register reads for GetI expression");
        case Iex_RdTmp:
            return get_guest_accesses_for_temp(expr->Iex.RdTmp.tmp, get_register_value, on_stmt_visit);
        case Iex_Qop:
        {
            auto &e = expr->Iex.Qop;
            auto a1 = get_guest_accesses(e.details->arg1, get_register_value, on_stmt_visit);
            auto a2 = get_guest_accesses(e.details->arg2, get_register_value, on_stmt_visit);
            auto a3 = get_guest_accesses(e.details->arg3, get_register_value, on_stmt_visit);
            auto a4 = get_guest_accesses(e.details->arg4, get_register_value, on_stmt_visit);
            a1.insert(a1.end(), a2.begin(), a2.end());
            a1.insert(a1.end(), a3.begin(), a3.end());
            a1.insert(a1.end(), a4.begin(), a4.end());
            a1.erase(filter_duplicates_inplace(a1.begin(), a1.end()), a1.end());
            return a1;
        }
        case Iex_Triop:
        {
            auto &e = expr->Iex.Triop;
            auto a1 = get_guest_accesses(e.details->arg1, get_register_value, on_stmt_visit);
            auto a2 = get_guest_accesses(e.details->arg2, get_register_value, on_stmt_visit);
            auto a3 = get_guest_accesses(e.details->arg3, get_register_value, on_stmt_visit);
            a1.insert(a1.end(), a2.begin(), a2.end());
            a1.insert(a1.end(), a3.begin(), a3.end());
            a1.erase(filter_duplicates_inplace(a1.begin(), a1.end()), a1.end());
            return a1;
        }
        case Iex_Binop:
        {
            auto &e = expr->Iex.Binop;
            auto a1 = get_guest_accesses(e.arg1, get_register_value, on_stmt_visit);
            auto a2 = get_guest_accesses(e.arg2, get_register_value, on_stmt_visit);
            a1.insert(a1.end(), a2.begin(), a2.end());
            a1.erase(filter_duplicates_inplace(a1.begin(), a1.end()), a1.end());
            return a1;
        }
        case Iex_Unop:
        {
            auto &e = expr->Iex.Unop;
            switch (e.op) {
                case Iop_Clz8x8:
                case Iop_Clz8x16:
                case Iop_Clz16x4:
                case Iop_Clz16x8:
                case Iop_Clz32:
                case Iop_Clz32x2:
                case Iop_Clz32x4:
                case Iop_Clz64:
                case Iop_Clz64x2:
                case Iop_ClzNat32:
                case Iop_ClzNat64:
                case Iop_Cls8x8:
                case Iop_Cls8x16:
                case Iop_Cls16x4:
                case Iop_Cls16x8:
                case Iop_Cls32x2:
                case Iop_Cls32x4:
                    /*
                     * Instructions that count leading ones or zeroes are treated as instructions
                     * that propagates taints implicitly, which we don't track.
                     */
                    return {};
                default:
                    return get_guest_accesses(expr->Iex.Unop.arg, get_register_value, on_stmt_visit);
            }
        }
        case Iex_Load:
        {
            auto &e = expr->Iex.Load;
            if (e.end != Iend_LE) {
                throw std::runtime_error("NYI: Big endianness");
            }
            uint64_t addr = eval_expr(e.addr, get_register_value);
            // Consider registers used for address calculation as part of the registers that are read
            auto addr_regs_accesses = get_guest_accesses(e.addr, get_register_value, on_stmt_visit);
            addr_regs_accesses.emplace_back(GuestAccess {
                 MemoryRegion::from_start_and_size(addr, (uint64_t) sizeofIRType(e.ty)),
                 AccessTarget::Memory,
                 AccessType::Read
            });
            return addr_regs_accesses;
        }
        case Iex_Const:
            return {};
        case Iex_ITE:
        {
            auto &e = expr->Iex.ITE;
            auto a1 = get_guest_accesses(e.iftrue, get_register_value, on_stmt_visit);
            auto a2 = get_guest_accesses(e.iffalse, get_register_value, on_stmt_visit);
            a1.insert(a1.end(), a2.begin(), a2.end());
            a1.erase(filter_duplicates_inplace(a1.begin(), a1.end()), a1.end());
            return a1;
        }
        case Iex_CCall:
        {
            auto res = std::vector<GuestAccess>();
            auto &e = expr->Iex.CCall;
            for (size_t i = 0; e.args[i] != nullptr; i++) {
                auto arg_reg_reads = get_guest_accesses(e.args[i], get_register_value, on_stmt_visit);
                res.insert(res.end(), arg_reg_reads.begin(), arg_reg_reads.end());
            }
            res.erase(filter_duplicates_inplace(res.begin(), res.end()), res.end());
            return res;
        }
        case Iex_VECRET:
            throw std::runtime_error("NYI: Register reads vor VECRET");
        case Iex_GSPTR:
            throw std::runtime_error("NYI: Register reads vor GSPTR");
    }
}

GuestModifications
IRSBResult::get_guest_modifications(size_t ins_i, std::function<uint64_t(Int)> get_register_value) {
    auto *irsb = get_irsb();
    validate_ins_i(ins_i);
    auto res = GuestModifications {};
    if (ins_i != get_ins_count() - 1 || irsb->jumpkind != Ijk_NoDecode) {
        std::vector<bool> visited_stmts((unsigned long) irsb->stmts_used, false);
        auto on_stmt_visit = [&] (size_t stmt) {
            if (stmt >= visited_stmts.size()) {
                throw std::runtime_error("Visited out-of-bounds statement");
            }
            visited_stmts[stmt] = true;
        };
        auto first_stmt = get_first_stmt_at_instruction(ins_i);
        auto last_stmt = (ins_i + 1 < get_ins_count()) ?
                get_first_stmt_at_instruction(ins_i + 1) - 1 : irsb_->stmts_used - 1;
        assert(first_stmt < last_stmt);
        // Collect guest modifications for each IR statement
        for (size_t i = first_stmt;
             i < irsb->stmts_used && irsb->stmts[i]->tag != Ist_IMark;
             i++) {
            auto stmt = irsb->stmts[i];
            auto modification = std::optional<GuestModification> {};
            switch (stmt->tag) {
                case Ist_IMark:
                    throw std::runtime_error("Unreachable");
                case Ist_NoOp:
                case Ist_AbiHint:
                case Ist_WrTmp:
                case Ist_MBE:
                case Ist_Exit:
                    break;
                case Ist_Put: {
                    auto &put = stmt->Ist.Put;
                    Int dest_register = put.offset;
                    auto expr = put.data;
                    modification = GuestModification {
                          .reads = get_guest_accesses(expr, get_register_value, on_stmt_visit),
                          .write = GuestAccess {
                                  MemoryRegion::from_start_and_size_signed(dest_register,
                                                                           sizeofIRType(typeOfIRExpr(irsb->tyenv, expr))),
                                  AccessTarget::Register,
                                  AccessType::Write
                          }
                    };
                }
                    break;
                case Ist_PutI:
                    throw std::runtime_error("NYI: PutI");
                case Ist_Store: {
                    auto &store = stmt->Ist.Store;
                    auto expr = store.data;
                    auto a1 = get_guest_accesses(expr, get_register_value, on_stmt_visit);
                    // Consider registers used for address calculation as part of the registers that are read
                    auto a2 = get_guest_accesses(store.addr, get_register_value, on_stmt_visit);
                    a1.insert(a1.end(), a2.begin(), a2.end());
                    modification = GuestModification {
                            .reads = a1,
                            .write = GuestAccess{
                                    MemoryRegion::from_start_and_size(
                                            eval_expr(store.addr, get_register_value),
                                            (uint64_t) sizeofIRType(typeOfIRExpr(irsb->tyenv, expr))),
                                    AccessTarget::Memory,
                                    AccessType::Write
                            }
                    };
                }
                    break;
                    // TODO: Conditional execution
                case Ist_LoadG:
                    throw std::runtime_error("NYI: LoadG");
                case Ist_StoreG:
                    throw std::runtime_error("NYI: StoreG");
                case Ist_CAS:
                    throw std::runtime_error("NYI: CAS");
                case Ist_LLSC: {
                    auto &llsc = stmt->Ist.LLSC;
                    if (llsc.storedata == nullptr) {
                        /*
                         * We transformed Load linked statements into regular load expressions
                         */
                        break;
                    } else {
                        LOGW("Returning an over-approximation for guest modifications of a non-deterministic store-conditional instruction");
                        auto ty = typeOfIRExpr(irsb->tyenv, llsc.storedata);
                        // Mark read: data that might be stored if store-conditional successful
                        auto a1 = get_guest_accesses(llsc.storedata, get_register_value, on_stmt_visit);
                        // Mark read: existing data if store-conditional is not successful
                        auto fake_load = IRExpr{
                                .tag = Iex_Load,
                                .Iex.Load = {
                                        .addr = llsc.addr,
                                        .ty = ty,
                                        .end = llsc.end
                                }
                        };
                        auto a2 = get_guest_accesses(&fake_load, get_register_value, on_stmt_visit);
                        a1.insert(a1.end(), a2.begin(), a2.end());
                        modification = GuestModification{
                                .reads = a1,
                                .write = GuestAccess{
                                        MemoryRegion::from_start_and_size(
                                                eval_expr(llsc.addr, get_register_value),
                                                (uint64_t) sizeofIRType(ty)),
                                        AccessTarget::Memory,
                                        AccessType::Write
                                }
                        };
                    }
                }
                    break;
                case Ist_Dirty: {
                    auto &dirty = stmt->Ist.Dirty;
                    auto dest_tmp = dirty.details->tmp;
                    LOGW("Dirty helper: t%d = %s()", dest_tmp, dirty.details->cee->name);
                    if (dirty.details->mFx != Ifx_None) {
                        throw std::runtime_error("NYI: dirty helper with memory access");
                    }
                    LOGW("Guest modifications for dirty helper: %s",
                         dirty.details->nFxState == 0 ? "none" : "");
                    for (int i = 0; i < dirty.details->nFxState; i++) {
                        auto &fxstate = dirty.details->fxState[i];
                        char *fxstr = NULL;
                        switch (fxstate.fx) {
                            case Ifx_None:
                                fxstr = const_cast<char *>("none");
                                break;
                            case Ifx_Read:
                                fxstr = const_cast<char *>("read");
                                break;
                            case Ifx_Write:
                                fxstr = const_cast<char *>("write");
                                break;
                            case Ifx_Modify:
                                fxstr = const_cast<char *>("modify");
                                break;
                        }
                        LOGW("FX state: type %s\ttarget: %d\tsize: %d", fxstr, fxstate.offset,
                             fxstate.size);
                    }

                    if (dirty.details->nFxState > 0) {
                        throw std::runtime_error(
                                "NYI: dirty guest modifications e.g. register writes without PUT IRStmt");
                    }

                    // Address of callee isn't exported in public headers, so we compare strings...
                    if (strcmp(dirty.details->cee->name, "arm64g_dirtyhelper_MRS_CNTVCT_EL0") == 0) {
                    } else {
                        throw std::runtime_error("Unsupported dirty helper");
                    }
                }
                    break;
            }
            if (modification) {
                res.rw_pairs.emplace_back(std::move(modification.value()));
                on_stmt_visit(i);
            }
        }
        // Handle pc = irsb->next, which is an implicit IRStmt executed at the end of the IRSB
        if (last_stmt == irsb->stmts_used - 1) {
            assert(irsb->offsIP == OFFSET_arm64_PC);
            res.rw_pairs.emplace_back(GuestModification {
                .reads = get_guest_accesses(irsb->next, get_register_value, on_stmt_visit),
                .write = GuestAccess(
                        MemoryRegion::from_start_and_size((uint64_t) irsb->offsIP, 8),
                        AccessTarget::Register,
                        AccessType::Write)
            });
        }
        for (size_t i = last_stmt; first_stmt <= i; --i) {
            if (!visited_stmts[i]) {
                if (irsb->stmts[i]->tag == Ist_WrTmp) {
                    auto unused_mods = get_guest_accesses(irsb->stmts[i]->Ist.WrTmp.data, get_register_value, on_stmt_visit);
                    for (const auto mod : unused_mods) {
                        if (mod.type == AccessType::Write) {
                            throw std::runtime_error("Unused guest accesses writes to a register or memory location");
                        }
                    }
                    res.unused_reads.insert(res.unused_reads.end(), unused_mods.begin(), unused_mods.end());
                }
            }
        }
    } else {
        // Instruction wasn't able to get decoded properly by LibVEX
        // We override memory accesses for certain instructions that we have encountered in
        // real-world applications

        // TODO: Handle unused_reads

        auto current_instruction = machine_instructions_[ins_i];

        if (has_llsc_override(ins_i)) {
            if (auto kind = get_llsc_kind(ins_i)) {
                if (*kind != LLSC_Kind::LOAD_LINKED && *kind != LLSC_Kind::STORE_CONDITIONAL) {
                    throw std::runtime_error(fmt::format("Unsupported irsb override: {}", *kind));
                }

                auto vex_llsc_memory_access_register = register_to_vex_region(aarch64::get_llsc_memory_access_register(current_instruction));
                // TODO: We could read the size bits from the instructions if we want to be more precise
                auto mem_access = MemoryRegion::from_start_and_size(get_register_value((Int)vex_llsc_memory_access_register.start_address), 8);
                auto transfer_registers = aarch64::get_llsc_transfer_registers(current_instruction);

                if (*kind == LLSC_Kind::LOAD_LINKED) {
                    for (size_t i = 0 ; i < transfer_registers.size(); i++) {
                        res.rw_pairs.emplace_back(GuestModification {
                                .reads = { GuestAccess(mem_access.add_offset(i * 8), AccessTarget::Memory, AccessType::Read) },
                                .write = GuestAccess(register_to_vex_region(transfer_registers[i]), AccessTarget::Register, AccessType::Write)
                        });
                    }
                } else {
                    auto sc_status_reg = aarch64::get_store_conditional_status_register(current_instruction);
                    if (sc_status_reg) {
                        // Status register isn't the zero register
                        res.rw_pairs.emplace_back(GuestModification {
                                .reads = {}, // Non-deterministic value that's either 0 or 1
                                .write = GuestAccess(register_to_vex_region(*sc_status_reg), AccessTarget::Register, AccessType::Write)
                        });
                    }
                    // Assume store-conditional succeeded
                    // TODO: Only lower bits are read when not using full 64-bit registers, but 32-bit ones (x vs w)
                    auto reads = std::vector<GuestAccess> {};
                    for (size_t i = 0 ; i < transfer_registers.size(); i++) {
                        res.rw_pairs.emplace_back(GuestModification {
                                .reads = {GuestAccess(register_to_vex_region(transfer_registers[i]), AccessTarget::Register, AccessType::Read)},
                                .write = GuestAccess(mem_access.add_offset(i * 8), AccessTarget::Memory, AccessType::Write)
                        });
                    }
                }
            } else {
                throw std::runtime_error("LLSC override found, but couldn't get LLSC kind");
            }
        } else if (aarch64::is_dc_zva(current_instruction)) {
            static uint64_t cache_line_size = 0;
            if (!cache_line_size) {
                asm("mrs %x0, dczid_el0"
                        : "=r"(cache_line_size));
                if (cache_line_size == 0) {
                    throw std::runtime_error("dczid_el0 returned 0");
                }
                auto word_count = 2ULL << (cache_line_size - 1);
                cache_line_size = 4 * word_count;
                assert(cache_line_size);
            }
            if (auto dst_addr_reg = aarch64::gp_reg_id_to_reg(current_instruction & 0x1f)) {
                res.rw_pairs.emplace_back(GuestModification {
                        .reads = {}, // zeroes
                        .write = GuestAccess(
                                MemoryRegion::from_start_and_size(
                                        get_register_value((Int)register_to_vex_region(*dst_addr_reg).start_address)
                                        , cache_line_size)
                                , AccessTarget::Memory, AccessType::Write)
                });
            } else {
                // Clear memory @ xzr
            }
        }
    }
    return res;
}

IRJumpKind IRSBResult::get_jump_kind() {
    return get_irsb()->jumpkind;
}

std::optional<LLSC_Kind> IRSBResult::get_llsc_kind(size_t ins_i) {
    auto override_it = llsc_overrides_.find(ins_i);
    if (override_it != llsc_overrides_.end()) {
        return override_it->second;
    }
    auto *irsb = get_irsb();
    for (size_t i = get_first_stmt_at_instruction(ins_i);
         i < irsb->stmts_used && irsb->stmts[i]->tag != Ist_IMark;
         i++) {
        auto *stmt = irsb->stmts[i];
        if (stmt->tag == Ist_MBE && stmt->Ist.MBE.event == Imbe_CancelReservation) {
            return LLSC_Kind::CLEAR_EXCLUSIVE;
        }
        if (stmt->tag == Ist_LLSC) {
            if (stmt->Ist.LLSC.storedata == nullptr) {
                return LLSC_Kind::LOAD_LINKED;
            } else {
                return LLSC_Kind::STORE_CONDITIONAL;
            }
        }
    }
    return std::nullopt;
}

bool IRSBResult::has_llsc_override(size_t ins_i) {
    auto override_it = llsc_overrides_.find(ins_i);
    return override_it != llsc_overrides_.end();
}

void IRSBResult::override_llsc_kind(size_t ins_i, LLSC_Kind kind) {
    validate_ins_i(ins_i);
    auto [it, inserted] = llsc_overrides_.try_emplace(ins_i, kind);
    if (!inserted) {
        throw std::runtime_error("Tried to override an instruction more than once");
    }
}

std::vector<std::unique_ptr<BasicBlockJump>> IRSBResult::get_jump_targets() {
    /*
     * We extract jump targets from Exit IR statements parts of the last instruction or the IRSB,
     * as well as the jump target of the IRSB itself
     *
     * Example of an IRSB whose jump targets can statically be determined (b.ne $pc - 0x30):
     *   ------ IMark(0x1000, 4, 0) ------
     *   t2 = GET:I64(280)
     *   t1 = Or64(t2,0x10:I64)
     *   t3 = GET:I64(288)
     *   t4 = GET:I64(296)
     *   t5 = GET:I64(304)
     *   t6 = arm64g_calculate_condition[mcx=0x9]{0x58bab29824}(t1,t3,t4,t5):I64
     *   t0 = 64to1(t6)
     *   if (t0) { PUT(272) = 0xFD0:I64; exit-Boring }
     *   PUT(272) = 0x1004:I64
     *   t7 = GET:I64(272)
     *   PUT(272) = t7; exit-Boring
     *
     * Example of an IRSB whose jump target cannot be statically determined (br x0):
     *   ------ IMark(0x1000, 4, 0) ------
     *   t0 = GET:I64(16)
     *   PUT(272) = t0
     *   t1 = GET:I64(272)
     *   PUT(272) = t1; exit-Boring
     */
    auto res = std::vector<std::unique_ptr<BasicBlockJump>> {};
    const auto irsb = get_irsb();
    auto pc_assign = std::optional<IRExpr *> {};
    const auto pc_offset = irsb->offsIP;
    for (size_t i = get_first_stmt_at_instruction(ins_count_ - 1); i < irsb->stmts_used; i++) {
        auto &stmt = irsb->stmts[i];
        switch (stmt->tag) {
            case Ist_Exit:
            {
                const auto &ins = stmt->Ist.Exit;
                if (ins.jk != Ijk_Boring) {
                    throw std::runtime_error("Non-boring jump-kind found in inline exit instruction");
                    /*
                    // We're only interested in regular jumps without other side-effects for now
                    res.emplace_back(std::make_unique<BasicBlockDynamicJump>());
                    continue;
                    */
                }
                const auto &jump_target = ins.dst;
                if (jump_target) {
                    if (jump_target->tag != Ico_U64) {
                        throw std::runtime_error(fmt::format("Jump target type reported by VEX isn't Ico_U64 but {}", jump_target->tag));
                    }
                    res.emplace_back(std::make_unique<BasicBlockStaticJump>(jump_target->Ico.U64));
                } else {
                    throw std::runtime_error("VEX jump target is NULL");
                }
            }
                break;
            case Ist_Put:
            {
                const auto &ins = stmt->Ist.Put;
                if (ins.offset == pc_offset) {
                    // Statement writes to program counter
                    if (pc_assign) {
                        constexpr auto msg = "Single instruction writes multiple times to program counter";
                        LOGE("%s. IRSB:", msg);
                        print_IRSB();
                        throw std::runtime_error(msg);
                    }
                    pc_assign = ins.data;
                }
            }
                break;
            case Ist_IMark:
                throw std::runtime_error("Got unexpected IMark in last instruction of IRSB");
            default:
                break;
        }
    }

    if (!pc_assign) {
        constexpr auto msg = "Last instruction of IRSB did contain any IR statements that writes to the program counter";
        LOGE("%s. IRSB:", msg);
        print_IRSB();
        throw std::runtime_error(msg);
    }
    bool accesses_regs = false;
    uint64_t IRSB_jump_target = eval_expr(*pc_assign, [&](Int) {
        accesses_regs = true;
        return 0;
    });
    if (accesses_regs) {
        res.emplace_back(std::make_unique<BasicBlockDynamicJump>());
    } else {
        res.emplace_back(std::make_unique<BasicBlockStaticJump>(IRSB_jump_target));
    }

    return res;
}

size_t IRSBResult::get_ins_count() {
    return ins_count_;
}

void IRSBResult::validate_ins_i(size_t ins_i) {
    if (ins_i >= get_ins_count())
        throw std::runtime_error(fmt::format(
                "Indexed instruction {} is out-of-bounds. Number of translated instructions for this IRSB: {}",
                ins_i, get_ins_count()));
}

void IRSBResult::print_IRSB() {
    ppIRSB(get_irsb());
}

void IRSBResult::print_ins_IRStmts(size_t ins_i) {
    auto irsb = get_irsb();
    validate_ins_i(ins_i);
    for (size_t i = get_first_stmt_at_instruction(ins_i); i < irsb->stmts_used; i++) {
        auto stmt = irsb->stmts[i];
        if (stmt->tag == Ist_IMark || stmt->tag == Ist_Exit) {
            return;
        }
        ppIRStmt(stmt);
        android_printf("\n");
    }
}

bool BasicBlockStaticJump::is_static_target() {
    return true;
}

uint64_t BasicBlockStaticJump::get_target() {
    return target_;
}

BasicBlockStaticJump::BasicBlockStaticJump(uint64_t target) : target_(target) {}

bool BasicBlockDynamicJump::is_static_target() {
    return false;
}

uint64_t BasicBlockDynamicJump::get_target() {
    throw std::runtime_error("Unable to get non-static jump target");
}
