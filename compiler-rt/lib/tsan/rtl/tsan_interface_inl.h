//===-- tsan_interface_inl.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
//===----------------------------------------------------------------------===//

#include "tsan_interface.h"
#include "tsan_rtl.h"
#include "sanitizer_common/sanitizer_ptrauth.h"

#define CALLERPC ((uptr)__builtin_return_address(0))

#define HOT_SECTION __attribute__((section("__tsan_flat")))

namespace __tsan {
ALWAYS_INLINE
void MemoryAccess(uptr pc, void *addr, int kAccessSizeLog, bool kIsWrite) {
  ThreadState *thr = cur_thread();
  DCHECK(!atomic_load_relaxed(thr->in_runtime));
  //ScopedRuntime sr(thr);
  MemoryAccess(thr, pc, (uptr)addr, kAccessSizeLog, kIsWrite, false);
}
} // namespace __tsan

using namespace __tsan;

HOT_SECTION void __tsan_read1(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog1, false);
}

HOT_SECTION void __tsan_read2(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog2, false);
}

HOT_SECTION void __tsan_read4(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog4, false);
}

HOT_SECTION void __tsan_read8(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog8, false);
}

HOT_SECTION void __tsan_write1(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog1, true);
}

HOT_SECTION void __tsan_write2(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog2, true);
}

HOT_SECTION void __tsan_write4(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog4, true);
}

HOT_SECTION void __tsan_write8(void *addr) {
  MemoryAccess(CALLERPC, addr, kSizeLog8, true);
}

HOT_SECTION void __tsan_read1_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog1, false);
}

HOT_SECTION void __tsan_read2_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog2, false);
}

HOT_SECTION void __tsan_read4_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog4, false);
}

HOT_SECTION void __tsan_read8_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog8, false);
}

HOT_SECTION void __tsan_write1_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog1, true);
}

HOT_SECTION void __tsan_write2_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog2, true);
}

HOT_SECTION void __tsan_write4_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog4, true);
}

HOT_SECTION void __tsan_write8_pc(void *addr, void *pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, kSizeLog8, true);
}

void __tsan_vptr_update(void **vptr_p, void *new_val) {
  if (*vptr_p == new_val)
    return;
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  thr->is_vptr_access = true;
  MemoryWrite(thr, CALLERPC, (uptr)vptr_p, kSizeLog8);
  thr->is_vptr_access = false;
}

void __tsan_vptr_read(void **vptr_p) {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  thr->is_vptr_access = true;
  MemoryRead(thr, CALLERPC, (uptr)vptr_p, kSizeLog8);
  thr->is_vptr_access = false;
}

HOT_SECTION void __tsan_func_entry(void *pc) {
  ThreadState *thr = cur_thread();
  //ScopedRuntime sr(thr);
  FuncEntry(thr, STRIP_PAC_PC(pc));
}

HOT_SECTION void __tsan_func_exit() {
  ThreadState *thr = cur_thread();
  //ScopedRuntime sr(thr);
  FuncExit(thr);
}

void __tsan_ignore_thread_begin() {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  ThreadIgnoreBegin(thr, CALLERPC);
}

void __tsan_ignore_thread_end() {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  ThreadIgnoreEnd(thr, CALLERPC);
}

void __tsan_read_range(void *addr, uptr size) {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  MemoryAccessRange(thr, CALLERPC, (uptr)addr, size, false);
}

void __tsan_write_range(void *addr, uptr size) {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  MemoryAccessRange(thr, CALLERPC, (uptr)addr, size, true);
}

void __tsan_read_range_pc(void *addr, uptr size, void *pc) {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  MemoryAccessRange(thr, STRIP_PAC_PC(pc), (uptr)addr, size, false);
}

void __tsan_write_range_pc(void *addr, uptr size, void *pc) {
  ThreadState *thr = cur_thread();
  ScopedRuntime sr(thr);
  MemoryAccessRange(thr, STRIP_PAC_PC(pc), (uptr)addr, size, true);
}

namespace __tsan {
  void* flat_funcs[] = {
    (void*)__tsan_read1,
    (void*)__tsan_read2,
    (void*)__tsan_read4,
    (void*)__tsan_read8,
    (void*)__tsan_write1,
    (void*)__tsan_write2,
    (void*)__tsan_write4,
    (void*)__tsan_write8,
    (void*)__tsan_read1_pc,
    (void*)__tsan_read2_pc,
    (void*)__tsan_read4_pc,
    (void*)__tsan_read8_pc,
    (void*)__tsan_write1_pc,
    (void*)__tsan_write2_pc,
    (void*)__tsan_write4_pc,
    (void*)__tsan_write8_pc,
    (void*)__tsan_func_entry,
    (void*)__tsan_func_exit,
    nullptr,
  };
}
