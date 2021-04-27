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

using namespace __tsan;

void __tsan_read1(void* addr) {
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, 1);
}

void __tsan_read2(void* addr) {
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, 2);
}

void __tsan_read4(void* addr) {
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, 4);
}

void __tsan_read8(void* addr) {
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, 8);
}

void __tsan_write1(void* addr) {
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, 1);
}

void __tsan_write2(void* addr) {
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, 2);
}

void __tsan_write4(void* addr) {
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, 4);
}

void __tsan_write8(void* addr) {
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, 8);
}

void __tsan_read1_pc(void* addr, void* pc) {
  MemoryRead(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 1);
}

void __tsan_read2_pc(void* addr, void* pc) {
  MemoryRead(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 2);
}

void __tsan_read4_pc(void* addr, void* pc) {
  MemoryRead(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 4);
}

void __tsan_read8_pc(void* addr, void* pc) {
  MemoryRead(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 8);
}

void __tsan_write1_pc(void* addr, void* pc) {
  MemoryWrite(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 1);
}

void __tsan_write2_pc(void* addr, void* pc) {
  MemoryWrite(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 2);
}

void __tsan_write4_pc(void* addr, void* pc) {
  MemoryWrite(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 4);
}

void __tsan_write8_pc(void* addr, void* pc) {
  MemoryWrite(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, 8);
}

ALWAYS_INLINE USED void __tsan_unaligned_read2(const void* addr) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 2, false);
}

ALWAYS_INLINE USED void __tsan_unaligned_read4(const void* addr) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 4, false);
}

ALWAYS_INLINE USED void __tsan_unaligned_read8(const void* addr) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, false);
}

ALWAYS_INLINE USED void __tsan_unaligned_write2(void* addr) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 2, true);
}

ALWAYS_INLINE USED void __tsan_unaligned_write4(void* addr) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 4, true);
}

ALWAYS_INLINE USED void __tsan_unaligned_write8(void* addr) {
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, true);
}

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
u16 __sanitizer_unaligned_load16(const uu16* addr) {
  __tsan_unaligned_read2(addr);
  return *addr;
}

SANITIZER_INTERFACE_ATTRIBUTE
u32 __sanitizer_unaligned_load32(const uu32* addr) {
  __tsan_unaligned_read4(addr);
  return *addr;
}

SANITIZER_INTERFACE_ATTRIBUTE
u64 __sanitizer_unaligned_load64(const uu64* addr) {
  __tsan_unaligned_read8(addr);
  return *addr;
}

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store16(uu16* addr, u16 v) {
  *addr = v;
  __tsan_unaligned_write2(addr);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store32(uu32* addr, u32 v) {
  *addr = v;
  __tsan_unaligned_write4(addr);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store64(uu64* addr, u64 v) {
  *addr = v;
  __tsan_unaligned_write8(addr);
}
}

void __tsan_vptr_update(void **vptr_p, void *new_val) {
  if (*vptr_p == new_val)
    return;
  ThreadState* thr = cur_thread();
  //!!! figure out how to turn this into fail call
  thr->is_vptr_access = true;
  MemoryWrite(thr, CALLERPC, (uptr)vptr_p, 8);
  thr->is_vptr_access = false;
}

void __tsan_vptr_read(void **vptr_p) {
  ThreadState *thr = cur_thread();
  thr->is_vptr_access = true;
  MemoryRead(thr, CALLERPC, (uptr)vptr_p, 8);
  thr->is_vptr_access = false;
}

void __tsan_func_entry(void* pc) {
  FuncEntry(cur_thread(), STRIP_PAC_PC(pc));
}

void __tsan_func_exit() {
  FuncExit(cur_thread());
}

void __tsan_ignore_thread_begin() {
  ThreadIgnoreBegin(cur_thread(), CALLERPC);
}

void __tsan_ignore_thread_end() {
  ThreadIgnoreEnd(cur_thread());
}

void __tsan_read_range(void *addr, uptr size) {
  MemoryAccessRange(cur_thread(), CALLERPC, (uptr)addr, size, false);
}

void __tsan_write_range(void *addr, uptr size) {
  MemoryAccessRange(cur_thread(), CALLERPC, (uptr)addr, size, true);
}

void __tsan_read_range_pc(void *addr, uptr size, void *pc) {
  MemoryAccessRange(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, size, false);
}

void __tsan_write_range_pc(void *addr, uptr size, void *pc) {
  MemoryAccessRange(cur_thread(), STRIP_PAC_PC(pc), (uptr)addr, size, true);
}
