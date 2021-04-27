//===-- tsan_rtl_thread.cpp -----------------------------------------------===//
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

#include "sanitizer_common/sanitizer_placement_new.h"
#include "tsan_rtl.h"
#include "tsan_mman.h"
#include "tsan_platform.h"
#include "tsan_report.h"
#include "tsan_sync.h"

namespace __tsan {

// ThreadContext implementation.

ThreadContext::ThreadContext(Tid tid)
  : ThreadContextBase(tid)
  , thr()
  , sync() {
}

#if !SANITIZER_GO
ThreadContext::~ThreadContext() {
}
#endif

void ThreadContext::OnDead() {
  CHECK_EQ(sync, nullptr);
}

void ThreadContext::OnJoined(void *arg) {
  ThreadState *caller_thr = static_cast<ThreadState *>(arg);
  AcquireImpl(caller_thr, 0, sync);
  Free(sync);
}

struct OnCreatedArgs {
  ThreadState *thr;
  uptr pc;
};

void ThreadContext::OnCreated(void *arg) {
  thr = 0;
  if (tid == kMainTid)
    return;
  OnCreatedArgs *args = static_cast<OnCreatedArgs *>(arg);
  if (!args->thr)  // GCD workers don't have a parent thread.
    return;
  ReleaseStoreImpl(args->thr, 0, &sync);
  creation_stack_id = CurrentStackId(args->thr, args->pc);
}

void ThreadContext::OnReset() {
  CHECK(!sync);
}

void ThreadContext::OnDetached(void *arg) {
  Free(sync);
}

struct OnStartedArgs {
  ThreadState *thr;
  /*
  uptr stk_addr;
  uptr stk_size;
  uptr tls_addr;
  uptr tls_size;
  */
};

void ThreadContext::OnStarted(void *arg) {
  OnStartedArgs *args = static_cast<OnStartedArgs*>(arg);
  thr = args->thr;
  DPrintf("#%d: ThreadStart\n", tid);
  new(thr) ThreadState(tid);
  if (common_flags()->detect_deadlocks)
    thr->dd_lt = ctx->dd->CreateLogicalThread(tid);
#if !SANITIZER_GO
  thr->is_inited = true;
#endif
  thr->tctx = this;
}

void ThreadContext::OnFinished() {
#if SANITIZER_GO
  Free(thr->shadow_stack);
  thr->shadow_stack_pos = nullptr;
  thr->shadow_stack_end = nullptr;
#endif
  if (!detached)
    ReleaseStoreImpl(thr, 0, &sync);

  if (common_flags()->detect_deadlocks)
    ctx->dd->DestroyLogicalThread(thr->dd_lt);
#if !SANITIZER_GO
  PlatformCleanUpThreadState(thr);
#endif
  thr->~ThreadState();
#if TSAN_COLLECT_STATS
  StatAggregate(ctx->stat, thr->stat);
#endif
  thr = 0;
}

#if !SANITIZER_GO
struct ThreadLeak {
  ThreadContext *tctx;
  int count;
};

static void MaybeReportThreadLeak(ThreadContextBase *tctx_base, void *arg) {
  Vector<ThreadLeak> &leaks = *(Vector<ThreadLeak>*)arg;
  ThreadContext *tctx = static_cast<ThreadContext*>(tctx_base);
  if (tctx->detached || tctx->status != ThreadStatusFinished)
    return;
  for (uptr i = 0; i < leaks.Size(); i++) {
    if (leaks[i].tctx->creation_stack_id == tctx->creation_stack_id) {
      leaks[i].count++;
      return;
    }
  }
  ThreadLeak leak = {tctx, 1};
  leaks.PushBack(leak);
}
#endif

#if !SANITIZER_GO
static void ReportIgnoresEnabled(ThreadContext *tctx, IgnoreSet *set) {
  if (tctx->tid == kMainTid) {
    Printf("ThreadSanitizer: main thread finished with ignores enabled\n");
  } else {
    Printf("ThreadSanitizer: thread T%d %s finished with ignores enabled,"
      " created at:\n", tctx->tid, tctx->name);
    PrintStack(SymbolizeStackId(tctx->creation_stack_id));
  }
  Printf("  One of the following ignores was not ended"
      " (in order of probability)\n");
  for (uptr i = 0; i < set->Size(); i++) {
    Printf("  Ignore was enabled at:\n");
    PrintStack(SymbolizeStackId(set->At(i)));
  }
  Die();
}

static void ThreadCheckIgnore(ThreadState *thr) {
  if (ctx->after_multithreaded_fork)
    return;
  if (thr->ignore_reads_and_writes)
    ReportIgnoresEnabled(thr->tctx, &thr->mop_ignore_set);
  if (thr->ignore_sync)
    ReportIgnoresEnabled(thr->tctx, &thr->sync_ignore_set);
}
#else
static void ThreadCheckIgnore(ThreadState *thr) {}
#endif

void ThreadFinalize(ThreadState *thr) {
  ThreadCheckIgnore(thr);
#if !SANITIZER_GO
  if (!ShouldReport(thr, ReportTypeThreadLeak))
    return;
  ThreadRegistryLock l(&ctx->thread_registry);
  Vector<ThreadLeak> leaks;
  ctx->thread_registry.RunCallbackForEachThreadLocked(
      MaybeReportThreadLeak, &leaks);
  for (uptr i = 0; i < leaks.Size(); i++) {
    ScopedReport rep(ReportTypeThreadLeak);
    rep.AddThread(leaks[i].tctx, true);
    rep.SetCount(leaks[i].count);
    OutputReport(thr, rep);
  }
#endif
}

int ThreadCount(ThreadState *thr) {
  uptr result;
  ctx->thread_registry.GetNumberOfThreads(0, 0, &result);
  return (int)result;
}

Tid ThreadCreate(ThreadState *thr, uptr pc, uptr uid, bool detached) {
  StatInc(thr, StatThreadCreate);
  OnCreatedArgs args = { thr, pc };
  Tid parent_tid = thr ? thr->tid : kInvalidTid;  // No parent for GCD workers.
  Tid tid =
      ctx->thread_registry.CreateThread(uid, detached, parent_tid, &args);
  if (tid != kMainTid)
    IncrementEpoch(thr, pc);
  DPrintf("#%d: ThreadCreate tid=%d uid=%zu\n", parent_tid, tid, uid);
  return tid;
}

void ThreadStart(ThreadState *thr, Tid tid, tid_t os_id,
                 ThreadType thread_type) {
  OnStartedArgs args = { thr /*, stk_addr, stk_size, tls_addr, tls_size */};
  ctx->thread_registry.StartThread(tid, os_id, thread_type, &args);

  SlotAttach(thr);

  AcquireImpl(thr, 0, thr->tctx->sync);
  Free(thr->tctx->sync);

  uptr stk_addr = 0;
  uptr stk_size = 0;
  uptr tls_addr = 0;
  uptr tls_size = 0;
#if !SANITIZER_GO
  if (thread_type != ThreadType::Fiber)
    GetThreadStackAndTls(tid == kMainTid, &stk_addr, &stk_size, &tls_addr, &tls_size);

  if (tid != kMainTid) {
    if (stk_addr && stk_size)
      MemoryRangeImitateWrite(thr, /*pc=*/ 1, stk_addr, stk_size);

    if (tls_addr && tls_size) ImitateTlsWrite(thr, tls_addr, tls_size);
  }
#endif
  thr->stk_addr = stk_addr;
  thr->stk_size = stk_size;
  thr->tls_addr = tls_addr;
  thr->tls_size = tls_size;
      
#if !SANITIZER_GO
  if (ctx->after_multithreaded_fork) {
    thr->ignore_interceptors++;
    ThreadIgnoreBegin(thr, 0);
    ThreadIgnoreSyncBegin(thr, 0);
  }
#endif
}

void ThreadFinish(ThreadState *thr) {
  ThreadCheckIgnore(thr);
  StatInc(thr, StatThreadFinish);
  if (thr->stk_addr && thr->stk_size)
    DontNeedShadowFor(thr->stk_addr, thr->stk_size);
  if (thr->tls_addr && thr->tls_size)
    DontNeedShadowFor(thr->tls_addr, thr->tls_size);
#if !SANITIZER_GO
  thr->is_dead = true;
  thr->ignore_interceptors = true;
#endif
  bool detached = thr->tctx->detached;
  ctx->thread_registry.FinishThread(thr->tid);
  if (!detached) {
    // at this point the thread not Running.
    //!!! IncrementEpoch(thr, 0);
#if SANITIZER_DEBUG && !SANITIZER_GO
    CHECK(thr->need_epoch_increment);
    thr->need_epoch_increment = false;
#endif
  }
  SlotDetach(thr);
}

struct ConsumeThreadContext {
  uptr uid;
  ThreadContextBase *tctx;
};

static bool ConsumeThreadByUid(ThreadContextBase *tctx, void *arg) {
  ConsumeThreadContext *findCtx = (ConsumeThreadContext *)arg;
  if (tctx->user_id == findCtx->uid && tctx->status != ThreadStatusInvalid) {
    if (findCtx->tctx) {
      // Ensure that user_id is unique. If it's not the case we are screwed.
      // Something went wrong before, but now there is no way to recover.
      // Returning a wrong thread is not an option, it may lead to very hard
      // to debug false positives (e.g. if we join a wrong thread).
      Report("ThreadSanitizer: dup thread with used id 0x%zx\n", findCtx->uid);
      Die();
    }
    findCtx->tctx = tctx;
    tctx->user_id = 0;
  }
  return false;
}

Tid ThreadConsumeTid(ThreadState *thr, uptr pc, uptr uid) {
  ConsumeThreadContext findCtx = {uid, nullptr};
  ctx->thread_registry.FindThread(ConsumeThreadByUid, &findCtx);
  Tid tid = findCtx.tctx ? findCtx.tctx->tid : kInvalidTid;
  DPrintf("#%d: ThreadTid uid=%zu tid=%d\n", thr->tid, uid, tid);
  return tid;
}

void ThreadJoin(ThreadState *thr, uptr pc, Tid tid) {
  CHECK_GT(tid, 0);
  DPrintf("#%d: ThreadJoin tid=%d\n", thr->tid, tid);
  ctx->thread_registry.JoinThread(tid, thr);
}

void ThreadDetach(ThreadState *thr, uptr pc, Tid tid) {
  CHECK_GT(tid, 0);
  ctx->thread_registry.DetachThread(tid, thr);
}

void ThreadNotJoined(ThreadState *thr, uptr pc, Tid tid, uptr uid) {
  CHECK_GT(tid, 0);
  ctx->thread_registry.SetThreadUserId(tid, uid);
}

void ThreadSetName(ThreadState *thr, const char *name) {
  ctx->thread_registry.SetThreadName(thr->tid, name);
}

void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr,
                       uptr size, bool is_write) { //!!! change all is_write to isRead
  if (size == 0)
    return;

  RawShadow *shadow_mem = (RawShadow*)MemToShadow(addr);
  DPrintf2("#%d: MemoryAccessRange: @%p %p size=%d is_write=%d\n",
      thr->tid, (void*)pc, (void*)addr,
      (int)size, is_write);

#if SANITIZER_DEBUG
  if (!IsAppMem(addr)) {
    Printf("Access to non app mem %zx\n", addr);
    DCHECK(IsAppMem(addr));
  }
  if (!IsAppMem(addr + size - 1)) {
    Printf("Access to non app mem %zx\n", addr + size - 1);
    DCHECK(IsAppMem(addr + size - 1));
  }
  if (!IsShadowMem((uptr)shadow_mem)) {
    Printf("Bad shadow addr %p (%zx)\n", shadow_mem, addr);
    DCHECK(IsShadowMem((uptr)shadow_mem));
  }
  if (!IsShadowMem((uptr)(shadow_mem + size * kShadowCnt / 8 - 1))) {
    Printf("Bad shadow addr %p (%zx)\n",
               shadow_mem + size * kShadowCnt / 8 - 1, addr + size - 1);
    DCHECK(IsShadowMem((uptr)(shadow_mem + size * kShadowCnt / 8 - 1)));
  }
#endif

  StatInc(thr, StatMopRange);

  if (*shadow_mem == Shadow::kShadowRodata) {
    DCHECK(!is_write);
    // Access to .rodata section, no races here.
    // Measurements show that it can be 10-20% of all memory accesses.
    StatInc(thr, StatMopRangeRodata);
    return;
  }

  if (thr->ignore_enabled_)
    return;

  TraceMemoryAccessRange(thr, pc, addr, size, !is_write, false);

  Shadow fast_state = thr->fast_state;

#if !SANITIZER_GO
  const bool old_range_access_race = thr->range_access_race;
  thr->range_access_race = 1;
#endif

  bool unaligned = (addr % kShadowCell) != 0;

  // Handle unaligned beginning, if any.
  for (; addr % kShadowCell && size; addr++, size--) { 
    const u32 kAccessSizeLog = kSizeLog1;
    Shadow cur(fast_state);
    cur.SetAccess(addr, kAccessSizeLog, !is_write, false, false);
    MemoryAccessImpl(thr, addr, kAccessSizeLog, is_write, false,
        shadow_mem, cur);
  }
  if (unaligned)
    shadow_mem += kShadowCnt;
  // Handle middle part, if any.
  for (; size >= kShadowCell; addr += kShadowCell, size -= kShadowCell) {
    const u32 kAccessSizeLog = kSizeLog8;
    Shadow cur(fast_state);
    cur.SetAccess(0, kAccessSizeLog, !is_write, false, false);
    MemoryAccessImpl(thr, addr, kAccessSizeLog, is_write, false,
        shadow_mem, cur);
    shadow_mem += kShadowCnt;
  }
  // Handle ending, if any.
  for (; size; addr++, size--) {
    const u32 kAccessSizeLog = kSizeLog1;
    Shadow cur(fast_state);
    cur.SetAccess(addr, kAccessSizeLog, !is_write, false, false);
    MemoryAccessImpl(thr, addr, kAccessSizeLog, is_write, false,
        shadow_mem, cur);
  }
#if !SANITIZER_GO
  thr->range_access_race = old_range_access_race;
#endif
}

#if !SANITIZER_GO
void FiberSwitchImpl(ThreadState *from, ThreadState *to) {
  Processor *proc = from->proc();
  ProcUnwire(proc, from);
  ProcWire(proc, to);
  set_cur_thread(to);
}

ThreadState *FiberCreate(ThreadState *thr, uptr pc, unsigned flags) {
  void *mem = Alloc(sizeof(ThreadState));
  ThreadState *fiber = static_cast<ThreadState *>(mem);
  internal_memset(fiber, 0, sizeof(*fiber));
  Tid tid = ThreadCreate(thr, pc, 0, true);
  FiberSwitchImpl(thr, fiber);
  ThreadStart(fiber, tid, 0, ThreadType::Fiber);
  FiberSwitchImpl(fiber, thr);
  return fiber;
}

void FiberDestroy(ThreadState *thr, uptr pc, ThreadState *fiber) {
  FiberSwitchImpl(thr, fiber);
  ThreadFinish(fiber);
  FiberSwitchImpl(fiber, thr);
  Free(fiber);
}

void FiberSwitch(ThreadState *thr, uptr pc,
                 ThreadState *fiber, unsigned flags) {
  if (!(flags & FiberSwitchFlagNoSync))
    Release(thr, pc, (uptr)fiber);
  FiberSwitchImpl(thr, fiber);
  if (!(flags & FiberSwitchFlagNoSync))
    Acquire(fiber, pc, (uptr)fiber);
}
#endif

}  // namespace __tsan
