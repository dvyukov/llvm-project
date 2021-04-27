//===-- tsan_interface.cpp ------------------------------------------------===//
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
#include "tsan_interface_ann.h"
#include "tsan_rtl.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_ptrauth.h"

#define CALLERPC ((uptr)__builtin_return_address(0))

using namespace __tsan;

void __tsan_init() {
  cur_thread_init();
  Initialize(cur_thread());
}

void __tsan_flush_memory() {
  // FlushShadowMemory();
}

void __tsan_read16(void *addr) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  MemoryRead(thr, pc, (uptr)addr, 8);
  MemoryRead(thr, pc, (uptr)addr + 8, 8);
}

void __tsan_write16(void *addr) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  MemoryWrite(thr, pc, (uptr)addr, 8);
  MemoryWrite(thr, pc, (uptr)addr + 8, 8);
}

void __tsan_read16_pc(void* addr, void* pc1) {
  uptr pc = STRIP_PAC_PC(pc1);
  ThreadState* thr = cur_thread();
  MemoryRead(thr, pc, (uptr)addr, 8);
  MemoryRead(thr, pc, (uptr)addr + 8, 8);
}

void __tsan_write16_pc(void* addr, void* pc1) {
  uptr pc = STRIP_PAC_PC(pc1);
  ThreadState* thr = cur_thread();
  MemoryWrite(thr, pc, (uptr)addr, 8);
  MemoryWrite(thr, pc, (uptr)addr + 8, 8);
}

// __tsan_unaligned_read/write calls are emitted by compiler.

void __tsan_unaligned_read16(const void *addr) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  UnalignedMemoryAccess(thr, pc, (uptr)addr, 8, false);
  UnalignedMemoryAccess(thr, pc, (uptr)addr + 8, 8, false);
}

void __tsan_unaligned_write16(void *addr) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  UnalignedMemoryAccess(thr, pc, (uptr)addr, 8, true);
  UnalignedMemoryAccess(thr, pc, (uptr)addr + 8, 8, true);
}

// __sanitizer_unaligned_load/store are for user instrumentation.

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void *__tsan_get_current_fiber() {
  return cur_thread();
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__tsan_create_fiber(unsigned flags) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  return FiberCreate(thr, pc, flags);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_destroy_fiber(void *fiber) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  FiberDestroy(thr, pc, static_cast<ThreadState*>(fiber));
}

SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_switch_to_fiber(void *fiber, unsigned flags) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  FiberSwitch(thr, pc, static_cast<ThreadState*>(fiber), flags);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __tsan_set_fiber_name(void *fiber, const char *name) {
  ThreadState* thr = cur_thread();
  ThreadSetName(thr, name);
}
}  // extern "C"

void __tsan_acquire(void *addr) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  Acquire(thr, pc, (uptr)addr);
}

void __tsan_release(void *addr) {
  uptr pc = CALLERPC;
  ThreadState* thr = cur_thread();
  Release(thr, pc, (uptr)addr);
}
