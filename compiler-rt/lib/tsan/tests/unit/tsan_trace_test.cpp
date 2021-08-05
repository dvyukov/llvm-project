//===-- tsan_trace_test.cpp -----------------------------------------------===//
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
#include "tsan_trace.h"

#include <pthread.h>

#include "gtest/gtest.h"
#include "tsan_rtl.h"

namespace __tsan {

using namespace v3;

TEST(Trace, Basic) {
  struct Thread {
    static void *Func(void *arg) {
      ThreadState *thr = cur_thread();
      TraceFunc(thr, 0x1000);
      CHECK(TryTraceMemoryAccess(thr, 0x2000, 0x3000, 8, kAccessRead));
      Lock lock1(&ctx->slot_mtx);
      ThreadRegistryLock lock2(&ctx->thread_registry);
      VarSizeStackTrace stk;
      MutexSet mset;
      uptr tag = kExternalTagMax;
      bool res =
          RestoreStack(thr->tid, EventTypeAccessExt, thr->sid, thr->epoch,
                       0x3000, 8, kAccessRead, &stk, &mset, &tag);
      CHECK(res);
      CHECK_EQ(stk.size, 2);
      CHECK_EQ(stk.trace[0], 0x1000);
      CHECK_EQ(stk.trace[1], 0x2000);
      CHECK_EQ(mset.Size(), 0);
      CHECK_EQ(tag, kExternalTagNone);
      return nullptr;
    }
  };
  pthread_t th;
  pthread_create(&th, nullptr, Thread::Func, nullptr);
  pthread_join(th, nullptr);
}

}  // namespace __tsan
