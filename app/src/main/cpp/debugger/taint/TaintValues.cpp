#include "TaintValues.h"

TaintValues::TaintValues(std::vector<arm64_reg> regs,
                         std::vector<TaintValues::RefToTaintedRegion> mem) :
                         regs(std::move(regs)), mem(std::move(mem)) {}
