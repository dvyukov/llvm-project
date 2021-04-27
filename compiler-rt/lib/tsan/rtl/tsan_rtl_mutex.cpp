//===-- tsan_rtl_mutex.cpp ------------------------------------------------===//
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

#include <sanitizer_common/sanitizer_deadlock_detector_interface.h>
#include <sanitizer_common/sanitizer_stackdepot.h>

#include "tsan_rtl.h"
#include "tsan_flags.h"
#include "tsan_sync.h"
#include "tsan_report.h"
#include "tsan_symbolize.h"
#include "tsan_platform.h"

namespace __tsan {

void ReportDeadlock(ThreadState *thr, uptr pc, DDReport *r);
void ReportDestroyLocked(ThreadState *thr, uptr pc, uptr addr, u32 last_lock, StackID creation_stack_id);

struct Callback final : public DDCallback {
  ThreadState *thr;
  uptr pc;

  Callback(ThreadState *thr, uptr pc)
      : thr(thr)
      , pc(pc) {
    DDCallback::pt = thr->proc()->dd_pt;
    DDCallback::lt = thr->dd_lt;
  }

  StackID Unwind() override { return CurrentStackId(thr, pc); }
  Tid UniqueTid() override { return thr->tid; }
};

void DDMutexInit(ThreadState *thr, uptr pc, SyncVar *s) {
  Callback cb(thr, pc);
  ctx->dd->MutexInit(&cb, &s->dd);
  s->dd.stk = s->creation_stack_id;
  s->dd.ctx = s->addr;
}

static void ReportMutexMisuse(ThreadState *thr, uptr pc, ReportType typ,
    uptr addr, StackID creation_stack_id) {
  // In Go, these misuses are either impossible, or detected by std lib,
  // or false positives (e.g. unlock in a different thread).
  if (SANITIZER_GO)
    return;
  if (!ShouldReport(thr, typ))
    return;
  ThreadRegistryLock l(&ctx->thread_registry);
  ScopedReport rep(typ);
  rep.AddMutex(addr, creation_stack_id);
  VarSizeStackTrace trace;
  ObtainCurrentStack(thr, pc, &trace);
  rep.AddStack(trace, true);
  rep.AddLocation(addr, 1);
  OutputReport(thr, rep);
}

void MutexCreate(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexCreate %zx flagz=0x%x\n", thr->tid, addr, flagz);
  StatInc(thr, StatMutexCreate);
  if (!(flagz & MutexFlagLinkerInit) && IsAppMem(addr)) {
    CHECK(!thr->is_freeing);
    thr->is_freeing = true;
    MemoryWrite(thr, pc, addr, kSizeLog1);
    thr->is_freeing = false;
  }
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  s->SetFlags(flagz & MutexCreationFlagMask);
  if (!SANITIZER_GO && s->creation_stack_id == kInvalidStackID)
    s->creation_stack_id = CurrentStackId(thr, pc);
  s->mtx.Unlock();
}

void MutexDestroy(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexDestroy %zx\n", thr->tid, addr);
  StatInc(thr, StatMutexDestroy);
  SyncVar *s = ctx->metamap.GetIfExistsAndLock(addr, true);
  if (s == 0)
    return;
  if ((flagz & MutexFlagLinkerInit)
      || s->IsFlagSet(MutexFlagLinkerInit)
      || ((flagz & MutexFlagNotStatic) && !s->IsFlagSet(MutexFlagNotStatic))) {
    // Destroy is no-op for linker-initialized mutexes.
    s->mtx.Unlock();
    return;
  }
  if (common_flags()->detect_deadlocks) {
    Callback cb(thr, pc);
    ctx->dd->MutexDestroy(&cb, &s->dd);
    ctx->dd->MutexInit(&cb, &s->dd);
  }
  bool unlock_locked = false;
  if (flags()->report_destroy_locked
      && s->owner_tid != kInvalidTid
      && !s->IsFlagSet(MutexFlagBroken)) {
    s->SetFlags(MutexFlagBroken);
    unlock_locked = true;
  }
  StackID creation_stack_id = s->creation_stack_id;
  u32 last_lock = s->last_lock;
  s->Reset();
  s->mtx.Unlock();
  s = nullptr;
  if (unlock_locked && ShouldReport(thr, ReportTypeMutexDestroyLocked))
    ReportDestroyLocked(thr, pc, addr, last_lock, creation_stack_id);
  thr->mset.Del(addr, true);
  // Imitate a memory write to catch unlock-destroy races.
  // Do this outside of sync mutex, because it can report a race which locks
  // sync mutexes.
  if (IsAppMem(addr)) {
    CHECK(!thr->is_freeing);
    thr->is_freeing = true;
    MemoryWrite(thr, pc, addr, kSizeLog1);
    thr->is_freeing = false;
  }
  // s will be destroyed and freed in MetaMap::FreeBlock.
}

void MutexPreLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexPreLock %zx flagz=0x%x\n", thr->tid, addr, flagz);
  if (!(flagz & MutexFlagTryLock) && common_flags()->detect_deadlocks) {
    SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, false);
    s->UpdateFlags(flagz);
    if (s->owner_tid != thr->tid) {
      Callback cb(thr, pc);
      ctx->dd->MutexBeforeLock(&cb, &s->dd, true);
      s->mtx.ReadUnlock();
      ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
    } else {
      s->mtx.ReadUnlock();
    }
  }
}

void MutexPostLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz, int rec) {
  DPrintf("#%d: MutexPostLock %zx flag=0x%x rec=%d\n",
      thr->tid, addr, flagz, rec);
  if (flagz & MutexFlagRecursiveLock)
    CHECK_GT(rec, 0);
  else
    rec = 1;
  if (IsAppMem(addr))
    MemoryReadAtomic(thr, pc, addr, kSizeLog1);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  s->UpdateFlags(flagz);
  TraceMutexLock(thr, EventTypeLock, pc, addr, s->creation_stack_id);
  bool report_double_lock = false;
  if (s->owner_tid == kInvalidTid) {
    CHECK_EQ(s->recursion, 0);
    s->owner_tid = thr->tid;
    s->last_lock = thr->fast_state.raw();
  } else if (s->owner_tid == thr->tid) {
    CHECK_GT(s->recursion, 0);
  } else if (flags()->report_mutex_bugs && !s->IsFlagSet(MutexFlagBroken)) {
    s->SetFlags(MutexFlagBroken);
    report_double_lock = true;
  }
  const bool first = s->recursion == 0;
  s->recursion += rec;
  if (first) {
    StatInc(thr, StatMutexLock);
    AcquireImpl(thr, pc, s->clock);
    AcquireImpl(thr, pc, s->read_clock);
  } else if (!s->IsFlagSet(MutexFlagWriteReentrant)) {
    StatInc(thr, StatMutexRecLock);
  }
  thr->mset.Add(addr, s->creation_stack_id, true);
  bool pre_lock = false;
  if (first && common_flags()->detect_deadlocks) {
    pre_lock = (flagz & MutexFlagDoPreLockOnPostLock) &&
        !(flagz & MutexFlagTryLock);
    Callback cb(thr, pc);
    if (pre_lock)
      ctx->dd->MutexBeforeLock(&cb, &s->dd, true);
    ctx->dd->MutexAfterLock(&cb, &s->dd, true, flagz & MutexFlagTryLock);
  }
  StackID creation_stack_id = s->creation_stack_id;
  s->mtx.Unlock();
  s = nullptr;   // Can't touch s after this point.
  if (report_double_lock)
    ReportMutexMisuse(thr, pc, ReportTypeMutexDoubleLock, addr, creation_stack_id);
  if (first && pre_lock && common_flags()->detect_deadlocks) {
    Callback cb(thr, pc);
    ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
  }
}

int MutexUnlock(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexUnlock %zx flagz=0x%x\n", thr->tid, addr, flagz);
  if (IsAppMem(addr))
    MemoryReadAtomic(thr, pc, addr, kSizeLog1);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  TraceMutexUnlock(thr, addr);
  int rec = 0;
  bool report_bad_unlock = false;
  if (!SANITIZER_GO && (s->recursion == 0 || s->owner_tid != thr->tid)) {
    if (flags()->report_mutex_bugs && !s->IsFlagSet(MutexFlagBroken)) {
      s->SetFlags(MutexFlagBroken);
      report_bad_unlock = true;
    }
  } else {
    rec = (flagz & MutexFlagRecursiveUnlock) ? s->recursion : 1;
    s->recursion -= rec;
    if (s->recursion == 0) {
      StatInc(thr, StatMutexUnlock);
      s->owner_tid = kInvalidTid;
      ReleaseStoreImpl(thr, pc, &s->clock);
    } else {
      StatInc(thr, StatMutexRecUnlock);
    }
  }
  thr->mset.Del(addr, true);
  if (common_flags()->detect_deadlocks && s->recursion == 0 &&
      !report_bad_unlock) {
    Callback cb(thr, pc);
    ctx->dd->MutexBeforeUnlock(&cb, &s->dd, true);
  }
  StackID creation_stack_id = s->creation_stack_id;
  s->mtx.Unlock();
  s = nullptr;   // Can't touch s after this point.
  IncrementEpoch(thr, pc);
  if (report_bad_unlock)
    ReportMutexMisuse(thr, pc, ReportTypeMutexBadUnlock, addr, creation_stack_id);
  if (common_flags()->detect_deadlocks && !report_bad_unlock) {
    Callback cb(thr, pc);
    ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
  }
  return rec;
}

void MutexPreReadLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexPreReadLock %zx flagz=0x%x\n", thr->tid, addr, flagz);
  if (!(flagz & MutexFlagTryLock) && common_flags()->detect_deadlocks) {
    SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, false);
    s->UpdateFlags(flagz);
    Callback cb(thr, pc);
    ctx->dd->MutexBeforeLock(&cb, &s->dd, false);
    s->mtx.ReadUnlock();
    ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
  }
}

void MutexPostReadLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz) {
  DPrintf("#%d: MutexPostReadLock %zx flagz=0x%x\n", thr->tid, addr, flagz);
  StatInc(thr, StatMutexReadLock);
  if (IsAppMem(addr))
    MemoryReadAtomic(thr, pc, addr, kSizeLog1);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, false);
  s->UpdateFlags(flagz);
  TraceMutexLock(thr, EventTypeRLock, pc, addr, s->creation_stack_id);
  bool report_bad_lock = false;
  if (s->owner_tid != kInvalidTid) {
    if (flags()->report_mutex_bugs && !s->IsFlagSet(MutexFlagBroken)) {
      s->SetFlags(MutexFlagBroken);
      report_bad_lock = true;
    }
  }
  AcquireImpl(thr, pc, s->clock);
  s->last_lock = thr->fast_state.raw();
  thr->mset.Add(addr, s->creation_stack_id, false);
  bool pre_lock = false;
  if (common_flags()->detect_deadlocks) {
    pre_lock = (flagz & MutexFlagDoPreLockOnPostLock) &&
        !(flagz & MutexFlagTryLock);
    Callback cb(thr, pc);
    if (pre_lock)
      ctx->dd->MutexBeforeLock(&cb, &s->dd, false);
    ctx->dd->MutexAfterLock(&cb, &s->dd, false, flagz & MutexFlagTryLock);
  }
  StackID creation_stack_id = s->creation_stack_id;
  s->mtx.ReadUnlock();
  s = nullptr;   // Can't touch s after this point.
  if (report_bad_lock)
    ReportMutexMisuse(thr, pc, ReportTypeMutexBadReadLock, addr, creation_stack_id);
  if (pre_lock  && common_flags()->detect_deadlocks) {
    Callback cb(thr, pc);
    ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
  }
}

void MutexReadUnlock(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: MutexReadUnlock %zx\n", thr->tid, addr);
  StatInc(thr, StatMutexReadUnlock);
  if (IsAppMem(addr))
    MemoryReadAtomic(thr, pc, addr, kSizeLog1);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  TraceMutexUnlock(thr, addr);
  bool report_bad_unlock = false;
  if (s->owner_tid != kInvalidTid) {
    if (flags()->report_mutex_bugs && !s->IsFlagSet(MutexFlagBroken)) {
      s->SetFlags(MutexFlagBroken);
      report_bad_unlock = true;
    }
  }
  ReleaseImpl(thr, pc, &s->read_clock);
  if (common_flags()->detect_deadlocks && s->recursion == 0) {
    Callback cb(thr, pc);
    ctx->dd->MutexBeforeUnlock(&cb, &s->dd, false);
  }
  StackID creation_stack_id = s->creation_stack_id;
  s->mtx.Unlock();
  s = nullptr;   // Can't touch s after this point.
  IncrementEpoch(thr, pc);
  thr->mset.Del(addr, false);
  if (report_bad_unlock)
    ReportMutexMisuse(thr, pc, ReportTypeMutexBadReadUnlock, addr, creation_stack_id);
  if (common_flags()->detect_deadlocks) {
    Callback cb(thr, pc);
    ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
  }
}

void MutexReadOrWriteUnlock(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: MutexReadOrWriteUnlock %zx\n", thr->tid, addr);
  if (IsAppMem(addr))
    MemoryReadAtomic(thr, pc, addr, kSizeLog1);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  TraceMutexUnlock(thr, addr);
  bool write = true;
  bool report_bad_unlock = false;
  if (s->owner_tid == kInvalidTid) {
    // Seems to be read unlock.
    write = false;
    StatInc(thr, StatMutexReadUnlock);
    ReleaseImpl(thr, pc, &s->read_clock);
  } else if (s->owner_tid == thr->tid) {
    // Seems to be write unlock.
    CHECK_GT(s->recursion, 0);
    s->recursion--;
    if (s->recursion == 0) {
      StatInc(thr, StatMutexUnlock);
      s->owner_tid = kInvalidTid;
      ReleaseStoreImpl(thr, pc, &s->clock);
    } else {
      StatInc(thr, StatMutexRecUnlock);
    }
  } else if (!s->IsFlagSet(MutexFlagBroken)) {
    s->SetFlags(MutexFlagBroken);
    report_bad_unlock = true;
  }
  thr->mset.Del(addr, write);
  if (common_flags()->detect_deadlocks && s->recursion == 0) {
    Callback cb(thr, pc);
    ctx->dd->MutexBeforeUnlock(&cb, &s->dd, write);
  }
  StackID creation_stack_id = s->creation_stack_id;
  s->mtx.Unlock();
  s = nullptr;   // Can't touch s after this point.
  IncrementEpoch(thr, pc);
  if (report_bad_unlock)
    ReportMutexMisuse(thr, pc, ReportTypeMutexBadUnlock, addr, creation_stack_id);
  if (common_flags()->detect_deadlocks) {
    Callback cb(thr, pc);
    ReportDeadlock(thr, pc, ctx->dd->GetReport(&cb));
  }
}

void MutexRepair(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: MutexRepair %zx\n", thr->tid, addr);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  s->owner_tid = kInvalidTid;
  s->recursion = 0;
  s->mtx.Unlock();
}

void MutexInvalidAccess(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: MutexInvalidAccess %zx\n", thr->tid, addr);
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  StackID creation_stack_id = s->creation_stack_id;
  s->mtx.Unlock();
  ReportMutexMisuse(thr, pc, ReportTypeMutexInvalidAccess, addr, creation_stack_id);
}

void Acquire(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: Acquire %zx\n", thr->tid, addr);
  if (thr->ignore_sync)
    return;
  SyncVar *s = ctx->metamap.GetIfExistsAndLock(addr, false);
  if (!s)
    return;
  AcquireImpl(thr, pc, s->clock);
  s->mtx.ReadUnlock();
}

void ReleaseStoreAcquire(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: ReleaseStoreAcquire %zx\n", thr->tid, addr);
  if (thr->ignore_sync)
    return;
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  ReleaseStoreAcquireImpl(thr, pc, &s->clock);
  s->mtx.Unlock();
  IncrementEpoch(thr, pc);
}

void Release(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: Release %zx\n", thr->tid, addr);
  if (thr->ignore_sync)
    return;
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  ReleaseImpl(thr, pc, &s->clock);
  s->mtx.Unlock();
  IncrementEpoch(thr, pc);
}

void ReleaseStore(ThreadState *thr, uptr pc, uptr addr) {
  DPrintf("#%d: ReleaseStore %zx\n", thr->tid, addr);
  if (thr->ignore_sync)
    return;
  SyncVar *s = ctx->metamap.GetOrCreateAndLock(thr, pc, addr, true);
  ReleaseStoreImpl(thr, pc, &s->clock);
  s->mtx.Unlock();
  IncrementEpoch(thr, pc);
}

void AcquireGlobal(ThreadState *thr, uptr pc) {
  DPrintf("#%d: AcquireGlobal\n", thr->tid);
  if (thr->ignore_sync)
    return;
  ThreadRegistryLock l(&ctx->thread_registry);
  for (auto& slot: ctx->slots)
    thr->clock.Set(slot.sid, (slot.thr ? slot.thr->clock : slot.clock).Get(slot.sid));
}

#if !SANITIZER_GO
void AfterSleep(ThreadState *thr, uptr pc) {
  DPrintf("#%d: AfterSleep\n", thr->tid);
  if (thr->ignore_sync)
    return;
  thr->last_sleep_stack_id = CurrentStackId(thr, pc);
  ThreadRegistryLock l(&ctx->thread_registry);
  for (auto& slot: ctx->slots)
    thr->last_sleep_clock.Set(slot.sid, (slot.thr ? slot.thr->clock : slot.clock).Get(slot.sid));
}
#endif

void AcquireImpl(ThreadState *thr, uptr pc, const VectorClock *c) {
  if (thr->ignore_sync || !c)
    return;
  thr->clock.Acquire(c);
  StatInc(thr, StatSyncAcquire);
}

void ReleaseStoreAcquireImpl(ThreadState *thr, uptr pc, VectorClock **c) {
  if (thr->ignore_sync)
    return;
  thr->clock.ReleaseStoreAcquire(c);
  thr->need_epoch_increment = true;
  StatInc(thr, StatSyncReleaseStoreAcquire);
}

void ReleaseImpl(ThreadState *thr, uptr pc, VectorClock **c) {
  if (thr->ignore_sync)
    return;
  thr->clock.Release(c);
  thr->need_epoch_increment = true;
  StatInc(thr, StatSyncRelease);
}

void ReleaseStoreImpl(ThreadState *thr, uptr pc, VectorClock **c) {
  if (thr->ignore_sync)
    return;
  thr->clock.ReleaseStore(c);
  thr->need_epoch_increment = true;
  StatInc(thr, StatSyncRelease);
}

void ReleaseAcquireImpl(ThreadState *thr, uptr pc, VectorClock **c) {
  if (thr->ignore_sync)
    return;
  thr->clock.ReleaseAcquire(c);
  thr->need_epoch_increment = true;
  StatInc(thr, StatSyncAcquire);
  StatInc(thr, StatSyncRelease);
}

void IncrementEpoch(ThreadState *thr, uptr pc) {
  if (!thr->need_epoch_increment)
    return;
  thr->need_epoch_increment = false;
  DCHECK_EQ(thr->tctx->status, ThreadStatusRunning);
  CheckNoLocks();
  TraceEvent(thr, EventTypeRelease);
  u16 epoch = static_cast<u16>(thr->fast_state.epoch()) + 1;
  if (epoch) {
    thr->fast_state.SetEpoch(static_cast<Epoch>(epoch));
    thr->clock.Set(thr->fast_state.sid(), thr->fast_state.epoch());
    return;
  }
  SlotDetach(thr);
  SlotAttach(thr);
}

void ReportDeadlock(ThreadState *thr, uptr pc, DDReport *r) {
  if (r == 0 || !ShouldReport(thr, ReportTypeDeadlock))
    return;
  ThreadRegistryLock l(&ctx->thread_registry);
  ScopedReport rep(ReportTypeDeadlock);
  for (int i = 0; i < r->n; i++) {
    rep.AddMutex(r->loop[i].mtx_ctx0, r->loop[i].stk[0]);
    if (r->loop[i].thr_ctx != kInvalidTid) {
      rep.AddUniqueTid(r->loop[i].thr_ctx);
      rep.AddThread(r->loop[i].thr_ctx);
    }
  }
  uptr dummy_pc = 0x42;
  for (int i = 0; i < r->n; i++) {
    for (int j = 0; j < (flags()->second_deadlock_stack ? 2 : 1); j++) {
      StackID stk = r->loop[i].stk[j];
      if (stk != kInvalidStackID) {
        rep.AddStack(StackDepotGet(stk), true);
      } else {
        // Sometimes we fail to extract the stack trace (FIXME: investigate),
        // but we should still produce some stack trace in the report.
        rep.AddStack(StackTrace(&dummy_pc, 1), true);
      }
    }
  }
  OutputReport(thr, rep);
}

void ReportDestroyLocked(ThreadState *thr, uptr pc, uptr addr, u32 last_lock, StackID creation_stack_id) {
    //!!! double check that we don't have this inversion in other places.
    MutexSet mset;
    Shadow last(last_lock);
    //!!! this won't restore read lock stack because type == EventTypeLock.
    Tid tid;
    VarSizeStackTrace trace[2];
    RestoreStack(EventTypeLock, last.sid(), last.epoch(), addr, 0, false, false, false, &tid, &trace[1], &mset);
    ThreadRegistryLock l(&ctx->thread_registry);
    ScopedReport rep(ReportTypeMutexDestroyLocked);
    rep.AddMutex(addr, creation_stack_id);
    ObtainCurrentStack(thr, pc, &trace[0]);
    rep.AddStack(trace[0], true);
    rep.AddStack(trace[1], true);
    rep.AddLocation(addr, 1);
    OutputReport(thr, rep);
}

}  // namespace __tsan
