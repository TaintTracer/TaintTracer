#include "BinderService.h"

BinderTransactionCtx::BinderTransactionCtx(BinderService &service) : service(service) {}

void BinderService::on_rx(BinderTransaction &tx, BinderDriver &driver, Process &proc,
                          FileDescriptorTable &fdtable) {}
