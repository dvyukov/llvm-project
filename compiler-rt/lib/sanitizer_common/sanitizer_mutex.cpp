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
    if (i < 1000)
      ;
    else if (i < 1010)
      internal_sched_yield();
    else
      internal_usleep(10);
    if (atomic_load(&state_, memory_order_relaxed) == 0
        && atomic_exchange(&state_, 1, memory_order_acquire) == 0)
        return;
  }
}
}
