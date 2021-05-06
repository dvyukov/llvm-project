//===-- tsan_rtl_report.cpp -----------------------------------------------===//
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

#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "tsan_platform.h"
#include "tsan_rtl.h"
#include "tsan_suppressions.h"
#include "tsan_symbolize.h"
#include "tsan_report.h"
#include "tsan_sync.h"
#include "tsan_mman.h"
#include "tsan_flags.h"
#include "tsan_fd.h"

namespace __tsan {

using namespace __sanitizer;

static ReportStack *SymbolizeStack(StackTrace trace);

void CheckFailed(const char *file, int line, const char *cond,
                     u64 v1, u64 v2) {
  // There is high probability that interceptors will check-fail as well,
  // on the other hand there is no sense in processing interceptors
  // since we are going to die soon.
  ScopedIgnoreInterceptors ignore;
#if !SANITIZER_GO
  ThreadState* thr = cur_thread();
  thr->nomalloc = false;
  thr->ignore_sync++;
  thr->ignore_reads_and_writes++;
#endif
  Printf("FATAL: ThreadSanitizer CHECK failed: "
         "%s:%d \"%s\" (0x%zx, 0x%zx)\n",
         file, line, cond, (uptr)v1, (uptr)v2);
  PrintCurrentStackSlow(StackTrace::GetCurrentPc());
  Die();
}

ExternalCallback::ExternalCallback() {
#if !SANITIZER_GO
  ThreadState *thr = cur_thread();
  //!!! should also ignore annotations
  thr->ignore_funcs_++;
  thr->ignore_interceptors++;
  ThreadIgnoreBegin(thr, 0, false);
#endif
}

ExternalCallback::~ExternalCallback() {
#if !SANITIZER_GO
  ThreadState *thr = cur_thread();
  CHECK(thr->ignore_funcs_);
  thr->ignore_funcs_--;
  thr->ignore_interceptors--;
  ThreadIgnoreEnd(thr, 0);
#endif
}

// Can be overriden by an application/test to intercept reports.
#ifdef TSAN_EXTERNAL_HOOKS
bool OnReport(const ReportDesc *rep, bool suppressed);
#else
SANITIZER_WEAK_CXX_DEFAULT_IMPL
bool OnReport(const ReportDesc *rep, bool suppressed) {
  (void)rep;
  return suppressed;
}
#endif

SANITIZER_WEAK_DEFAULT_IMPL
void __tsan_on_report(const ReportDesc *rep) {
  (void)rep;
}

static void StackStripMain(SymbolizedStack *frames) {
  SymbolizedStack *last_frame = nullptr;
  SymbolizedStack *last_frame2 = nullptr;
  for (SymbolizedStack *cur = frames; cur; cur = cur->next) {
    last_frame2 = last_frame;
    last_frame = cur;
  }

  if (last_frame2 == 0)
    return;
#if !SANITIZER_GO
  const char *last = last_frame->info.function;
  const char *last2 = last_frame2->info.function;
  // Strip frame above 'main'
  if (last2 && 0 == internal_strcmp(last2, "main")) {
    last_frame->ClearAll();
    last_frame2->next = nullptr;
  // Strip our internal thread start routine.
  } else if (last && 0 == internal_strcmp(last, "__tsan_thread_start_func")) {
    last_frame->ClearAll();
    last_frame2->next = nullptr;
  // Strip global ctors init.
  } else if (last && (0 == internal_strcmp(last, "__do_global_ctors_aux") ||
      0 == internal_strcmp(last, "__libc_csu_init"))) {
    last_frame->ClearAll();
    last_frame2->next = nullptr;
  // If both are 0, then we probably just failed to symbolize.
  } else if (last || last2) {
    // Ensure that we recovered stack completely. Trimmed stack
    // can actually happen if we do not instrument some code,
    // so it's only a debug print. However we must try hard to not miss it
    // due to our fault.
    DPrintf("Bottom stack frame is missed\n");
  }
#else
  // The last frame always point into runtime (gosched0, goexit0, runtime.main).
  last_frame->ClearAll();
  last_frame2->next = nullptr;
#endif
}

ReportStack *SymbolizeStackId(StackID stack_id) {
  if (stack_id == kInvalidStackID)
    return nullptr;
  StackTrace stack = StackDepotGet(stack_id);
  if (stack.trace == nullptr)
    return nullptr;
  return SymbolizeStack(stack);
}

static ReportStack *SymbolizeStack(StackTrace trace) {
  if (trace.size == 0)
    return 0;
  SymbolizedStack *top = nullptr;
  for (uptr si = 0; si < trace.size; si++) {
    const uptr pc = trace.trace[si];
    uptr pc1 = pc;
    // We obtain the return address, but we're interested in the previous
    // instruction.
    if ((pc & kExternalPCBit) == 0)
      pc1 = StackTrace::GetPreviousInstructionPc(pc);
    SymbolizedStack *ent = SymbolizeCode(pc1);
    CHECK_NE(ent, 0);
    SymbolizedStack *last = ent;
    while (last->next) {
      last->info.address = pc;  // restore original pc for report
      last = last->next;
    }
    last->info.address = pc;  // restore original pc for report
    last->next = top;
    top = ent;
  }
  StackStripMain(top);

  auto stack = New<ReportStack>();
  stack->frames = top;
  return stack;
}

bool ShouldReport(ThreadState *thr, ReportType typ) {
  // We set thr->suppress_reports in the fork context.
  // Taking any locking in the fork context can lead to deadlocks.
  // If any locks are already taken, it's too late to do this check.
  CheckNoLocks();
  // For the same reason check we didn't lock thread_registry yet.
  if (SANITIZER_DEBUG)
    ThreadRegistryLock l(&ctx->thread_registry);
  if (!flags()->report_bugs || thr->suppress_reports)
    return false;
  switch (typ) {
    case ReportTypeSignalUnsafe:
      return flags()->report_signal_unsafe;
    case ReportTypeThreadLeak:
#if !SANITIZER_GO
      // It's impossible to join phantom threads
      // in the child after fork.
      if (ctx->after_multithreaded_fork)
        return false;
#endif
      return flags()->report_thread_leaks;
    case ReportTypeMutexDestroyLocked:
      return flags()->report_destroy_locked;
    default:
      return true;
  }
}

ScopedReportBase::ScopedReportBase(ReportType typ, uptr tag) {
  ctx->thread_registry.CheckLocked();
  rep_ = New<ReportDesc>();
  rep_->typ = typ;
  rep_->tag = tag;
  ctx->report_mtx.Lock();
}

ScopedReportBase::~ScopedReportBase() {
  ctx->report_mtx.Unlock();
  DestroyAndFree(rep_);
}

void ScopedReportBase::AddStack(StackTrace stack, bool suppressable) {
  ReportStack **rs = rep_->stacks.PushBack();
  *rs = SymbolizeStack(stack);
  (*rs)->suppressable = suppressable;
}

void ScopedReportBase::AddMemoryAccess(uptr addr, uptr external_tag, Shadow s, Tid tid,
                                       StackTrace stack, const MutexSet *mset) {
  auto mop = New<ReportMop>();
  rep_->mops.PushBack(mop);
  mop->tid = tid;
  mop->addr = addr + s.addr0();
  mop->size = s.size();
  mop->write = s.IsWrite();
  mop->atomic = s.IsAtomic();
  mop->stack = SymbolizeStack(stack);
  mop->external_tag = external_tag;
  if (mop->stack)
    mop->stack->suppressable = true;
  for (uptr i = 0; i < mset->Size(); i++) {
    MutexSet::Desc d = mset->Get(i);
    int id = this->AddMutex(d.addr, d.stack_id);
    ReportMopMutex mtx = {id, d.write};
    mop->mset.PushBack(mtx);
  }
}

void ScopedReportBase::AddUniqueTid(Tid unique_tid) {
  rep_->unique_tids.PushBack(unique_tid);
}

void ScopedReportBase::AddThread(const ThreadContext *tctx, bool suppressable) {
  for (uptr i = 0; i < rep_->threads.Size(); i++) {
    if (rep_->threads[i]->id == tctx->tid)
      return;
  }
  auto rt = New<ReportThread>();
  rep_->threads.PushBack(rt);
  rt->id = tctx->tid;
  rt->os_id = tctx->os_id;
  rt->running = (tctx->status == ThreadStatusRunning);
  rt->name = internal_strdup(tctx->name);
  rt->parent_tid = tctx->parent_tid;
  rt->thread_type = tctx->thread_type;
  rt->stack = 0;
  rt->stack = SymbolizeStackId(tctx->creation_stack_id);
  if (rt->stack)
    rt->stack->suppressable = suppressable;
}

#if !SANITIZER_GO
static ThreadContext *FindThreadByTidLocked(Tid tid) {
  ctx->thread_registry.CheckLocked();
  return static_cast<ThreadContext*>(
      ctx->thread_registry.GetThreadLocked(tid));
}

static bool IsInStackOrTls(ThreadContextBase *tctx_base, void *arg) {
  uptr addr = (uptr)arg;
  ThreadContext *tctx = static_cast<ThreadContext*>(tctx_base);
  if (tctx->status != ThreadStatusRunning)
    return false;
  ThreadState *thr = tctx->thr;
  CHECK(thr);
  return ((addr >= thr->stk_addr && addr < thr->stk_addr + thr->stk_size) ||
          (addr >= thr->tls_addr && addr < thr->tls_addr + thr->tls_size));
}

ThreadContext *IsThreadStackOrTls(uptr addr, bool *is_stack) {
  ctx->thread_registry.CheckLocked();
  ThreadContext *tctx = static_cast<ThreadContext*>(
      ctx->thread_registry.FindThreadContextLocked(IsInStackOrTls,
                                                    (void*)addr));
  if (!tctx)
    return 0;
  ThreadState *thr = tctx->thr;
  CHECK(thr);
  *is_stack = (addr >= thr->stk_addr && addr < thr->stk_addr + thr->stk_size);
  return tctx;
}
#endif

void ScopedReportBase::AddThread(Tid tid, bool suppressable) {
#if !SANITIZER_GO
  if (const ThreadContext *tctx = FindThreadByTidLocked(tid))
    AddThread(tctx, suppressable);
#endif
}

int ScopedReportBase::AddMutex(uptr addr, StackID creation_stack_id) {
  for (uptr i = 0; i < rep_->mutexes.Size(); i++) {
    auto rm = rep_->mutexes[i];
    if (rm->addr == addr)
      return rm->id;
  }
  auto rm = New<ReportMutex>();
  rep_->mutexes.PushBack(rm);
  rm->id = rep_->mutexes.Size() - 1;
  rm->addr = addr;
  rm->stack = SymbolizeStackId(creation_stack_id);
  return rm->id;
}

void ScopedReportBase::AddLocation(uptr addr, uptr size) {
  if (addr == 0)
    return;
#if !SANITIZER_GO
  int fd = -1;
  Tid create_tid = kInvalidTid;
  StackID create_stack = kInvalidStackID;
  if (FdLocation(addr, &fd, &create_tid, &create_stack)) {
    auto loc = New<ReportLocation>();
    loc->type = ReportLocationFD;
    loc->fd = fd;
    loc->tid = create_tid;
    loc->stack = SymbolizeStackId(create_stack);
    rep_->locs.PushBack(loc);
    AddThread(create_tid);
    return;
  }
  MBlock *b = 0;
  Allocator *a = allocator();
  if (a->PointerIsMine((void*)addr)) {
    void *block_begin = a->GetBlockBegin((void*)addr);
    if (block_begin)
      b = ctx->metamap.GetBlock((uptr)block_begin);
  }
  if (b != 0) {
    ThreadContext *tctx = FindThreadByTidLocked(b->tid);
    auto loc = New<ReportLocation>();
    loc->type = ReportLocationHeap;
    loc->heap_chunk_start = (uptr)allocator()->GetBlockBegin((void *)addr);
    loc->heap_chunk_size = b->siz;
    loc->external_tag = b->tag;
    loc->tid = tctx ? tctx->tid : b->tid;
    loc->stack = SymbolizeStackId(b->stk);
    rep_->locs.PushBack(loc);
    if (tctx)
      AddThread(tctx);
    return;
  }
  bool is_stack = false;
  if (ThreadContext *tctx = IsThreadStackOrTls(addr, &is_stack)) {
    auto loc = New<ReportLocation>();
    loc->type = is_stack ? ReportLocationStack : ReportLocationTLS;
    loc->tid = tctx->tid;
    rep_->locs.PushBack(loc);
    AddThread(tctx);
  }
#endif
  if (ReportLocation *loc = SymbolizeData(addr)) {
    loc->suppressable = true;
    rep_->locs.PushBack(loc);
    return;
  }
}

#if !SANITIZER_GO
void ScopedReportBase::AddSleep(StackID stack_id) {
  rep_->sleep = SymbolizeStackId(stack_id);
}
#endif

void ScopedReportBase::SetCount(int count) { rep_->count = count; }

const ReportDesc *ScopedReportBase::GetReport() const { return rep_; }

ScopedReport::ScopedReport(ReportType typ, uptr tag)
    : ScopedReportBase(typ, tag) {}

ScopedReport::~ScopedReport() {}

uptr RestoreAddr(uptr addr) {
#if SANITIZER_GO
  return addr;
#else
  const uptr kRegionIndicator = 0x060000000000ull;
  switch (addr & kRegionIndicator) {
  case Mapping::kLoAppMemBeg & kRegionIndicator:
//Printf("XXX: addr=0x%zx lo -> 0x%zx\n", addr, addr);
    return addr;
  case Mapping::kHiAppMemBeg & kRegionIndicator:
//Printf("XXX: addr=0x%zx hi -> 0x%zx\n", addr, addr | 0x780000000000ull);
    return addr | 0x780000000000ull;
  case Mapping::kHeapMemBeg & kRegionIndicator:
//Printf("XXX: addr=0x%zx heap -> 0x%zx\n", addr, addr | 0x780000000000ull);
    return addr | 0x780000000000ull;
  case Mapping::kMidAppMemBeg & kRegionIndicator:
    //!!! this does not restore full range up to kMidAppMemEnd.
    // It has 0x56 which matches kHiAppMemBeg above.
//Printf("XXX: addr=0x%zx mid -> 0x%zx\n", addr, addr | 0x500000000000ull);
    return addr | 0x500000000000ull;
  }
  CHECK(0);
  return addr;
#endif
}

uptr RestorePC(uptr addr, bool isExternal) {
#if SANITIZER_GO
  return addr;
#else
  const uptr kRegionIndicator = 0x060000000000ull;
  switch (addr & kRegionIndicator) {
  case Mapping::kLoAppMemBeg & kRegionIndicator:
//Printf("XXX: addr=0x%zx lo -> 0x%zx\n", addr, addr);
    return addr;
  case Mapping::kHiAppMemBeg & kRegionIndicator:
//Printf("XXX: addr=0x%zx hi -> 0x%zx\n", addr, addr | 0x780000000000ull);
    return addr | 0x500000000000ull;
  case Mapping::kHeapMemBeg & kRegionIndicator:
//Printf("XXX: addr=0x%zx heap -> 0x%zx\n", addr, addr | 0x780000000000ull);
    return addr | 0x780000000000ull;
  case Mapping::kMidAppMemBeg & kRegionIndicator:
    //!!! this does not restore full range up to kMidAppMemEnd.
    // It has 0x56 which matches kHiAppMemBeg above.
//Printf("XXX: addr=0x%zx mid -> 0x%zx\n", addr, addr | 0x500000000000ull);
    return addr | 0x500000000000ull;
  }
  CHECK(0);
  return addr;
#endif

  //!!! return RestoreAddr(pc) | (isExternal ? kExternalPCBit : 0);
}

template<typename Func>
void TraceReplay(TracePart* first, TracePart* last, Event* last_pos, Epoch epoch, Func f) {
  Tid evTid = kInvalidTid;
  Epoch evEpoch = kEpochZero;
  TracePart* part = first;
  for (;;) {
    // Note: an event can't start in the last element.
    // Since an event can take up to 2 elements,
    // we ensure we have at least 2 before adding an event.
    Event* end = &part->events[ARRAY_SIZE(part->events) - 1];
    if (part == last)
      end = last_pos;
    for (Event* evp = &part->events[0]; evp < end; evp++) {
      Event* evp0 = evp;
      if (!evp->isAccess) {
        switch (evp->type) {
        case EventTypeAttach: {
          auto ev = reinterpret_cast<EventAttach*>(evp);
          evTid = static_cast<Tid>(ev->tid);
        }
        [[fallthrough]];
        case EventTypeRelease:
          CHECK_NE(evTid, kInvalidTid);
          evEpoch = EpochInc(evEpoch);
          if (evEpoch > epoch)
            return;
          break;
        case EventTypeAccessEx:
          [[fallthrough]];
        case EventTypeLock:
          [[fallthrough]];
        case EventTypeRLock:
          evp++;
        }
      }
      f(evTid, evEpoch, evp0);
    }
    if (part == last)
      return;
    part = part->next;
    CHECK(part);
  }
  CHECK(0);
}

Tid RestoreTid(TracePart* first, TracePart* last, Event* last_pos, Epoch epoch) {
  Tid tid = kInvalidTid;
  TraceReplay(first, last, last_pos, epoch, [&](Tid evTid, Epoch evEpoch, Event* evp) {
    if (evEpoch == epoch)
      tid = evTid;
  });
  return tid;
} 

void RestoreStack(EventType type, Sid sid, Epoch epoch, uptr addr, uptr size, bool isRead, bool isAtomic, bool isFreed, Tid* ptid, VarSizeStackTrace *stk,
                  MutexSet *pmset, uptr *tag) {
  // This function restores stack trace and mutex set for the thread/epoch.
  // It does so by getting stack trace and mutex set at the beginning of
  // trace part, and then replaying the trace till the given epoch.
  DPrintf2("RestoreStack: sid=%u@%u addr=0x%zx/%zu type=%u/%u/%u\n",
      static_cast<u32>(sid), static_cast<u32>(epoch),
      addr, size, isRead, isAtomic, isFreed);

  TidSlot* slot = &ctx->slots[static_cast<uptr>(sid)];
  Trace* trace = &slot->trace;
  TracePart* last_part;
  Event* last_pos;
  {
    SpinMutexLock lock(&trace->mtx);
    last_part = trace->current;
    last_pos = trace->pos;
    if (slot->thr)
      last_pos = (Event*)atomic_load_relaxed(&slot->thr->trace_pos);
  }
  Tid tid = kInvalidTid;
  TraceReplay(trace->first, last_part, last_pos, epoch, [&](Tid evTid, Epoch evEpoch, Event* evp) {
    if (evEpoch == epoch)
      tid = evTid;
  });
  DPrintf2("RestoreStack: tid=%u\n", tid);
  *ptid = tid;
  if (tid == kInvalidTid)
    return;
  CHECK_NE(tid, kInvalidTid);

  ctx->thread_registry.Lock();
  ThreadContext *tctx = static_cast<ThreadContext*>(
        ctx->thread_registry.GetThreadLocked(tid));
  ctx->thread_registry.Unlock();
  CHECK(tctx);
  Vector<uptr> stack;
  stack.Resize(tctx->startStack.size + 64);
  for (uptr i = 0; i < tctx->startStack.size; i++) {
    stack[i] = tctx->startStack.trace[i];
    DPrintf2("  #%02zu: pc=%zx\n", i, tctx->startStack.trace[i]);
  }
  uptr pos = tctx->startStack.size;
  uptr prev_pc = 0;
  MutexSet mset = tctx->startMutexSet;
  TraceReplay(trace->first, last_part, last_pos, epoch, [&](Tid evTid, Epoch evEpoch, Event* evp) {
    if (evTid != tid)
      return;
    if (evp->isAccess) {
      auto ev = reinterpret_cast<EventAccess*>(evp);
      //!!! also check access size and type (read/atomic).
      uptr evAddr = RestoreAddr(ev->addr);
      uptr evSize = 1 << ev->sizeLog;
      uptr evPC = (prev_pc & ~kExternalPCBit) + ev->pcDelta - (1 << 14);
      evPC = RestorePC(evPC, ev->isExternalPC); //!!! is this fine?
      prev_pc = evPC;
      DPrintf2("  Access: pc=0x%zx addr=0x%llx/%llu type=%llu/%llu\n",
          evPC, evAddr, evSize, ev->isRead, ev->isAtomic);
      if (type == EventTypeAccessEx &&
          evEpoch == epoch &&
          addr >= evAddr &&
          addr + size <= evAddr + evSize &&
          isRead == ev->isRead &&
          isAtomic == ev->isAtomic
          && !isFreed) {
        DPrintf2("    MATCHED\n");
        stack[pos] = evPC;
        stk->Init(&stack[0], pos + 1);
        *pmset = mset;
      }
      return;
    }
    switch (evp->type) {
    case EventTypeAccessEx: {
      auto ev = reinterpret_cast<EventAccessEx*>(evp);
      uptr evAddr = RestoreAddr(ev->addr);
      uptr evSize = (ev->sizeHi << 13) + ev->sizeLo;
      uptr evPC = RestorePC(ev->pc, ev->isExternalPC);
      prev_pc = evPC;
      DPrintf2("  AccessEx: pc=0x%zx addr=0x%llx/%llu type=%llu/%llu/%llu\n",
          evPC, evAddr, evSize, ev->isRead, ev->isAtomic, ev->isFreed);
      //!!! also check access size and type (read/atomic).
      if (type == EventTypeAccessEx && evEpoch == epoch && addr >= evAddr && addr + size <= evAddr + evSize &&
          isRead == ev->isRead && isAtomic == ev->isAtomic && isFreed == ev->isFreed) {
        DPrintf2("    MATCHED\n");
        stack[pos] = evPC;
        stk->Init(&stack[0], pos + 1);
        *pmset = mset;
      }
      break;
    }
    case EventTypeFuncEnter: {
      auto ev = reinterpret_cast<EventPC*>(evp);
      uptr evPC = RestorePC(ev->pc, ev->isExternalPC);
      DPrintf2("  FuncEnter: pc=0x%zx\n", evPC);
      if (stack.Size() < pos + 2)
        stack.Resize(pos + 2);
      stack[pos++] = evPC;
      break;
    }
    case EventTypeFuncExit:
      DPrintf2("  FuncExit\n");
      CHECK_GT(pos, 0);
      pos--;
      break;
    case EventTypeLock:
      [[fallthrough]];
    case  EventTypeRLock: {
      auto ev = reinterpret_cast<EventLock*>(evp);
      bool isWrite = ev->type == EventTypeLock;
      uptr evAddr = RestoreAddr(ev->addr);
      uptr evPC = RestorePC(ev->pc, ev->isExternalPC);
      StackID stackID = static_cast<StackID>((ev->stackIDHi << 16) + ev->stackIDLo);
      DPrintf2("  Lock: pc=0x%zx addr=0x%llx stack=%u write=%d\n",
          evPC, evAddr, stackID, isWrite);
      mset.Add(evAddr, stackID, isWrite);
      if (type == EventTypeLock && evEpoch == epoch && addr == evAddr) {
        DPrintf2("    MATCHED\n");
        stack[pos] = evPC;
        stk->Init(&stack[0], pos + 1);
        *pmset = mset;
      }
      break;
    }
    case EventTypeUnlock: {
      auto ev = reinterpret_cast<EventUnlock*>(evp);
      uptr evAddr = RestoreAddr(ev->addr);
      DPrintf2("  Unlock: addr=0x%llx\n", evAddr);
      mset.Del(evAddr);
      break;
    }}
  });
  ExtractTagFromStack(stk, tag);
}

static bool FindRacyStacks(const RacyStacks &hash) {
  for (uptr i = 0; i < ctx->racy_stacks.Size(); i++) {
    if (hash == ctx->racy_stacks[i]) {
      VPrintf(2, "ThreadSanitizer: suppressing report as doubled (stack)\n");
      return true;
    }
  }
  return false;
}

static bool HandleRacyStacks(ThreadState *thr, VarSizeStackTrace traces[2]) {
  if (!flags()->suppress_equal_stacks)
    return false;
  RacyStacks hash;
  hash.hash[0] = md5_hash(traces[0].trace, traces[0].size * sizeof(uptr));
  hash.hash[1] = md5_hash(traces[1].trace, traces[1].size * sizeof(uptr));
  {
    ReadLock lock(&ctx->racy_mtx);
    if (FindRacyStacks(hash))
      return true;
  }
  Lock lock(&ctx->racy_mtx);
  if (FindRacyStacks(hash))
    return true;
  ctx->racy_stacks.PushBack(hash);
  return false;
}

bool RacyStacks::operator==(const RacyStacks &other) const {
  if (hash[0] == other.hash[0] && hash[1] == other.hash[1])
    return true;
  if (hash[0] == other.hash[1] && hash[1] == other.hash[0])
    return true;
  return false;
}
  
static bool FindRacyAddress(const RacyAddress &ra0) {
  for (uptr i = 0; i < ctx->racy_addresses.Size(); i++) {
    RacyAddress ra2 = ctx->racy_addresses[i];
    uptr maxbeg = max(ra0.addr_min, ra2.addr_min);
    uptr minend = min(ra0.addr_max, ra2.addr_max);
    if (maxbeg < minend) {
      VPrintf(2, "ThreadSanitizer: suppressing report as doubled (addr)\n");
      return true;
    }
  }
  return false;
}

static bool HandleRacyAddress(ThreadState *thr, uptr addr_min, uptr addr_max) {
  if (!flags()->suppress_equal_addresses)
    return false;
  RacyAddress ra0 = {addr_min, addr_max};
  {
    ReadLock lock(&ctx->racy_mtx);
    if (FindRacyAddress(ra0))
      return true;
  }
  Lock lock(&ctx->racy_mtx);
  if (FindRacyAddress(ra0))
    return true;
  ctx->racy_addresses.PushBack(ra0);
  return false;
}

bool OutputReport(ThreadState *thr, const ScopedReport &srep) {
  // These should have been checked in ShouldReport.
  // It's too late to check them here, we have already taken locks.
  CHECK(flags()->report_bugs);
  CHECK(!thr->suppress_reports);
  atomic_store_relaxed(&ctx->last_symbolize_time_ns, NanoTime());
  const ReportDesc *rep = srep.GetReport();
  CHECK_EQ(thr->current_report, nullptr);
  thr->current_report = rep;
  Suppression *supp = 0;
  uptr pc_or_addr = 0;
  for (uptr i = 0; pc_or_addr == 0 && i < rep->mops.Size(); i++)
    pc_or_addr = IsSuppressed(rep->typ, rep->mops[i]->stack, &supp);
  for (uptr i = 0; pc_or_addr == 0 && i < rep->stacks.Size(); i++)
    pc_or_addr = IsSuppressed(rep->typ, rep->stacks[i], &supp);
  for (uptr i = 0; pc_or_addr == 0 && i < rep->threads.Size(); i++)
    pc_or_addr = IsSuppressed(rep->typ, rep->threads[i]->stack, &supp);
  for (uptr i = 0; pc_or_addr == 0 && i < rep->locs.Size(); i++)
    pc_or_addr = IsSuppressed(rep->typ, rep->locs[i], &supp);
  if (pc_or_addr != 0) {
    Lock lock(&ctx->fired_suppressions_mtx);
    FiredSuppression s = {srep.GetReport()->typ, pc_or_addr, supp};
    ctx->fired_suppressions.push_back(s);
  }
  {
    bool old_is_freeing = thr->is_freeing;
    thr->is_freeing = false;
    bool suppressed = OnReport(rep, pc_or_addr != 0);
    thr->is_freeing = old_is_freeing;
    if (suppressed) {
      thr->current_report = nullptr;
      return false;
    }
  }
  PrintReport(rep);
  {
    ExternalCallback cb;
    __tsan_on_report(rep);
  }
  ctx->nreported++;
  if (flags()->halt_on_error)
    Die();
  thr->current_report = nullptr;
  return true;
}

bool IsFiredSuppression(Context *ctx, ReportType type, StackTrace trace) {
  ReadLock lock(&ctx->fired_suppressions_mtx);
  for (uptr k = 0; k < ctx->fired_suppressions.size(); k++) {
    if (ctx->fired_suppressions[k].type != type)
      continue;
    for (uptr j = 0; j < trace.size; j++) {
      FiredSuppression *s = &ctx->fired_suppressions[k];
      if (trace.trace[j] == s->pc_or_addr) {
        if (s->supp)
          atomic_fetch_add(&s->supp->hit_count, 1, memory_order_relaxed);
        return true;
      }
    }
  }
  return false;
}

static bool IsFiredSuppression(Context *ctx, ReportType type, uptr addr) {
  ReadLock lock(&ctx->fired_suppressions_mtx);
  for (uptr k = 0; k < ctx->fired_suppressions.size(); k++) {
    if (ctx->fired_suppressions[k].type != type)
      continue;
    FiredSuppression *s = &ctx->fired_suppressions[k];
    if (addr == s->pc_or_addr) {
      if (s->supp)
        atomic_fetch_add(&s->supp->hit_count, 1, memory_order_relaxed);
      return true;
    }
  }
  return false;
}

static bool RaceBetweenAtomicAndFree(ThreadState *thr, Shadow cur, Shadow old) {
  CHECK(!(cur.IsAtomic() && old.IsAtomic()));
  if (!cur.IsAtomic() && !old.IsAtomic())
    return true;
  if (cur.IsAtomic() && old.IsFreed())
    return true;
  if (old.IsAtomic() && thr->is_freeing)
    return true;
  return false;
}

char* DumpShadow(char* buf, RawShadow raw);

struct ScopedInSymbolizer {
  ScopedInSymbolizer() {
    EnterSymbolizer();
  }
  ~ScopedInSymbolizer() {
    ExitSymbolizer();
  }
};

void ReportRace(ThreadState *thr, RawShadow* shadow_mem, Shadow cur, Shadow old) {
  CheckNoLocks();

  // Symbolizer makes lots of intercepted calls. If we try to process them,
  // at best it will cause deadlocks on internal mutexes.
  ScopedIgnoreInterceptors ignore;
  ScopedInSymbolizer sis;

  if (!ShouldReport(thr, ReportTypeRace))
    return;
  if (!flags()->report_atomic_races && !RaceBetweenAtomicAndFree(thr, cur, old))
    return;
#if !SANITIZER_GO
  // Don't report more than one race in the same range access.
  // First, it's just unnecessary and can produce lots of reports.
  // Second, thr->trace_prev_pc that we use below may become invalid.
  // The scenario where this happens is rather elaborate and requires
  // an instrumented __sanitizer_report_error_summary callback and
  // a __tsan_symbolize_external callback and a race during a range memory
  // access larger than 8 bytes. MemoryAccessRange adds the current PC to
  // the trace and starts processing memory accesses. A first memory access
  // triggers a race, we report it and call the instrumented
  // __sanitizer_report_error_summary, which adds more stuff to the trace
  // since it is intrumented. Then a second memory access in MemoryAccessRange
  // also triggers a race and we get here and use thr->trace_prev_pc
  // which is incorrect now.
  // test/tsan/double_race.cpp contains a test case for this.
  if (thr->range_access_race) {
    if (thr->range_access_race > 1)
      return;
    thr->range_access_race++;
  }
#endif

  Printf("CUR: sid=%u epoch=%u\n", (u32)thr->fast_state.sid(), (u32)thr->fast_state.epoch());
  char buf[128];
  Printf("CUR: %s\n", DumpShadow(buf, cur.raw()));
  Printf("OLD: %s\n", DumpShadow(buf, old.raw()));

  uptr addr = ShadowToMem((uptr)shadow_mem);
  const uptr kMop = 2;
  Shadow s[2] = {cur, old};
  uptr addr0 = addr + s[0].addr0();
  uptr addr1 = addr + s[1].addr0();
  uptr end0 = addr0 + s[0].size();
  uptr end1 = addr1 + s[1].size();
  uptr addr_min = min(addr0, addr1);
  uptr addr_max = max(end0, end1);
  if (IsExpectedReport(addr_min, addr_max - addr_min))
    return;
  if (HandleRacyAddress(thr, addr_min, addr_max))
    return;

  ReportType typ = ReportTypeRace;
  if (thr->is_vptr_access && s[1].IsFreed())
    typ = ReportTypeVptrUseAfterFree;
  else if (thr->is_vptr_access)
    typ = ReportTypeVptrRace;
  else if (s[1].IsFreed())
    typ = ReportTypeUseAfterFree;

  if (IsFiredSuppression(ctx, typ, addr))
    return;

  Tid tids[kMop] = {thr->tid, kInvalidTid};
  VarSizeStackTrace traces[kMop];
  uptr tags[kMop] = {kExternalTagNone};

  ObtainCurrentStack(thr, thr->trace_prev_pc, &traces[0], &tags[0]);
  if (IsFiredSuppression(ctx, typ, traces[0]))
    return;

  // MutexSet is too large to live on stack.
  Vector<u64> mset_buffer;
  mset_buffer.Resize(sizeof(MutexSet) / sizeof(u64) + 1);
  MutexSet* mset1 = new(&mset_buffer[0]) MutexSet();
  MutexSet *mset[2] = {&thr->mset, mset1};

  RestoreStack(EventTypeAccessEx, s[1].sid(), s[1].epoch(), addr1, s[1].size(), s[1].IsRead(), s[1].IsAtomic(), s[1].IsFreed(), &tids[1], &traces[1], mset[1], &tags[1]);
  if (IsFiredSuppression(ctx, typ, traces[1]))
    return;

  if (HandleRacyStacks(thr, traces))
    return;

  // If any of the accesses has a tag, treat this as an "external" race.
  uptr tag = kExternalTagNone;
  for (uptr i = 0; i < kMop; i++) {
    if (tags[i] != kExternalTagNone) {
      typ = ReportTypeExternalRace;
      tag = tags[i];
      break;
    }
  }

  ThreadRegistryLock l0(&ctx->thread_registry);
  ScopedReport rep(typ, tag);
  for (uptr i = 0; i < kMop; i++)
    rep.AddMemoryAccess(addr, tags[i], s[i], tids[i], traces[i], mset[i]);

  for (uptr i = 0; i < kMop; i++) {
    //ThreadContext *tctx = static_cast<ThreadContext*>(
    //    ctx->thread_registry.GetThreadLocked(tids[i]));
    //rep.AddThread(tctx);
  }

  rep.AddLocation(addr_min, addr_max - addr_min);

#if !SANITIZER_GO
  if (!s[1].IsFreed() && s[1].epoch() <= thr->last_sleep_clock.Get(s[1].sid()))
      rep.AddSleep(thr->last_sleep_stack_id);
#endif

  OutputReport(thr, rep);
}

void PrintCurrentStack(ThreadState *thr, uptr pc) {
  VarSizeStackTrace trace;
  ObtainCurrentStack(thr, pc, &trace);
  PrintStack(SymbolizeStack(trace));
}

// Always inlining PrintCurrentStackSlow, because LocatePcInTrace assumes
// __sanitizer_print_stack_trace exists in the actual unwinded stack, but
// tail-call to PrintCurrentStackSlow breaks this assumption because
// __sanitizer_print_stack_trace disappears after tail-call.
// However, this solution is not reliable enough, please see dvyukov's comment
// http://reviews.llvm.org/D19148#406208
// Also see PR27280 comment 2 and 3 for breaking examples and analysis.
ALWAYS_INLINE
void PrintCurrentStackSlow(uptr pc) {
#if !SANITIZER_GO
  uptr bp = GET_CURRENT_FRAME();
  auto ptrace = New<BufferedStackTrace>();
  ptrace->Unwind(pc, bp, nullptr, false);

  for (uptr i = 0; i < ptrace->size / 2; i++) {
    uptr tmp = ptrace->trace_buffer[i];
    ptrace->trace_buffer[i] = ptrace->trace_buffer[ptrace->size - i - 1];
    ptrace->trace_buffer[ptrace->size - i - 1] = tmp;
  }
  PrintStack(SymbolizeStack(*ptrace));
#endif
}

}  // namespace __tsan

using namespace __tsan;

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  PrintCurrentStackSlow(StackTrace::GetCurrentPc());
}
}  // extern "C"
