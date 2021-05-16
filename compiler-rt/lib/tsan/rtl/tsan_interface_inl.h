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

#if TSAN_FAST_FLAT
#  define FLAT_SECTION __attribute__((section("__tsan_flat")))
#else
#  define FLAT_SECTION
#endif

namespace __tsan {
ALWAYS_INLINE
void MemoryAccess(uptr pc, void* addr, int kAccessSize, bool kIsWrite) {
  ThreadState* thr = cur_thread();
  if (!TSAN_FAST_FLAT && thr->in_symbolizer)
    return;
  MaybeScopedRuntime<TSAN_FAST_FLAT> rt(thr);
  MemoryAccess<!TSAN_FAST_FLAT>(thr, pc, (uptr)addr, kAccessSize, kIsWrite,
                                false);
}
} // namespace __tsan

using namespace __tsan;

FLAT_SECTION void __tsan_read1(void* addr) {
  MemoryAccess(CALLERPC, addr, 1, false);
}

FLAT_SECTION void __tsan_read2(void* addr) {
  MemoryAccess(CALLERPC, addr, 2, false);
}

FLAT_SECTION void __tsan_read4(void* addr) {
  MemoryAccess(CALLERPC, addr, 4, false);
}

FLAT_SECTION void __tsan_read8(void* addr) {
  MemoryAccess(CALLERPC, addr, 8, false);
}

FLAT_SECTION void __tsan_write1(void* addr) {
  MemoryAccess(CALLERPC, addr, 1, true);
}

FLAT_SECTION void __tsan_write2(void* addr) {
  MemoryAccess(CALLERPC, addr, 2, true);
}

FLAT_SECTION void __tsan_write4(void* addr) {
  MemoryAccess(CALLERPC, addr, 4, true);
}

FLAT_SECTION void __tsan_write8(void* addr) {
  MemoryAccess(CALLERPC, addr, 8, true);
}

FLAT_SECTION void __tsan_read1_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 1, false);
}

FLAT_SECTION void __tsan_read2_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 2, false);
}

FLAT_SECTION void __tsan_read4_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 4, false);
}

FLAT_SECTION void __tsan_read8_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 8, false);
}

FLAT_SECTION void __tsan_write1_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 1, true);
}

FLAT_SECTION void __tsan_write2_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 2, true);
}

FLAT_SECTION void __tsan_write4_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 4, true);
}

FLAT_SECTION void __tsan_write8_pc(void* addr, void* pc) {
  MemoryAccess(STRIP_PAC_PC(pc), addr, 8, true);
}

void __tsan_vptr_update(void **vptr_p, void *new_val) {
  if (*vptr_p == new_val)
    return;
  ThreadState* thr = cur_thread();
  if (thr->in_symbolizer)
    return;
  ScopedRuntime sr(thr);
  thr->is_vptr_access = true;
  MemoryWrite(thr, CALLERPC, (uptr)vptr_p, 8);
  thr->is_vptr_access = false;
}

void __tsan_vptr_read(void **vptr_p) {
  ThreadState *thr = cur_thread();
  if (thr->in_symbolizer)
    return;
  ScopedRuntime sr(thr);
  thr->is_vptr_access = true;
  MemoryRead(thr, CALLERPC, (uptr)vptr_p, 8);
  thr->is_vptr_access = false;
}

FLAT_SECTION void __tsan_func_entry(void* pc) {
  ThreadState* thr = cur_thread();
  if (!TSAN_FAST_FLAT && thr->in_symbolizer)
    return;
  MaybeScopedRuntime<TSAN_FAST_FLAT> rt(thr);
  FuncEntry<!TSAN_FAST_FLAT>(thr, STRIP_PAC_PC(pc));
}

FLAT_SECTION void __tsan_func_exit() {
  ThreadState* thr = cur_thread();
  if (!TSAN_FAST_FLAT && thr->in_symbolizer)
    return;
  MaybeScopedRuntime<TSAN_FAST_FLAT> rt(thr);
  FuncExit<!TSAN_FAST_FLAT>(thr);
}

void __tsan_ignore_thread_begin() {
  ThreadState* thr = cur_thread();
  ScopedRuntime sr(thr);
  ThreadIgnoreBegin(thr, CALLERPC);
}

void __tsan_ignore_thread_end() {
  ThreadState* thr = cur_thread();
  ScopedRuntime sr(thr);
  ThreadIgnoreEnd(thr);
}

void __tsan_read_range(void *addr, uptr size) {
  ThreadState* thr = cur_thread();
  MemoryAccessRange(thr, CALLERPC, (uptr)addr, size, false);
}

void __tsan_write_range(void *addr, uptr size) {
  ThreadState* thr = cur_thread();
  MemoryAccessRange(thr, CALLERPC, (uptr)addr, size, true);
}

void __tsan_read_range_pc(void *addr, uptr size, void *pc) {
  ThreadState* thr = cur_thread();
  MemoryAccessRange(thr, STRIP_PAC_PC(pc), (uptr)addr, size, false);
}

void __tsan_write_range_pc(void *addr, uptr size, void *pc) {
  ThreadState* thr = cur_thread();
  MemoryAccessRange(thr, STRIP_PAC_PC(pc), (uptr)addr, size, true);
}

#if TSAN_FAST_FLAT
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
#endif
