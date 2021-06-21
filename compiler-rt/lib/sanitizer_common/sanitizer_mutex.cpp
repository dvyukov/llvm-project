//===-- sanitizer_mutex.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between AddressSanitizer and ThreadSanitizer
// run-time libraries.
//===----------------------------------------------------------------------===//

#include "sanitizer_mutex.h"

namespace __sanitizer {

void StaticSpinMutex::LockSlow() {
  for (int i = 0;; i++) {
    if (i > 1000)
      internal_sched_yield();
    if (atomic_load(&state_, memory_order_relaxed) == 0
        && atomic_exchange(&state_, 1, memory_order_acquire) == 0)
        return;
  }
}

/*
void Mutex::LockSlow(u64 state) {
  //!!! decrement kWriterInc, set kWriteLocked, reset kWriterWoken is waited

  for (;;) {
    if ((state & (kWriteLocked | kWriterMask)) == 0) {
      u64 inc = (state & kReaderMask) * kLeavingReaderInc;
      DCHECK(inc);
      state = atomic_fetch_add(&state_, inc, memory_order_relaxed);
      if (((state + inc) & kLeavingReaderMask) == 0)
        return;
  }
  writers_.Wait();
  
  //!!! who resets kWriterWoken?
  //!!! who decrements kWriterInc?
}

void Mutex::UnlockSlow(u64 state) {
  if ((state & kWriterMask) != 0)
    writers_.Post();
  else
    readers_.Post(state & kReaderMask);
}

void Mutex::ReadUnlockSlow(u64 state) {
  DCHECK_NE(state & kReaderMask, 0);
  state = atomic_fetch_sub(&state_, kLeavingReaderInc, memory_order_relaxed);
  if (((state - kLeavingReaderInc) & kLeavingReaderMask) == 0)
    writers_.Post();
}
*/
}
