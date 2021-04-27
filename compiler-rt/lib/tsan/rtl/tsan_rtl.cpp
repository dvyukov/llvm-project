//===-- tsan_rtl.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// Main file (entry points) for the TSan run-time.
//===----------------------------------------------------------------------===//

#include "tsan_rtl.h"

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
#include "tsan_defs.h"
#include "tsan_interface.h"
#include "tsan_mman.h"
#include "tsan_platform.h"
#include "tsan_suppressions.h"
#include "tsan_symbolize.h"
#include "ubsan/ubsan_init.h"

volatile int __tsan_resumed = 0;

extern "C" void __tsan_resume() {
  __tsan_resumed = 1;
}

extern "C" void __tsan_dump() {
  using namespace __tsan;
  Printf("DUMP: reset_pending=%u\n", atomic_load_relaxed(&ctx->reset_pending));
  for (auto& slot : ctx->slots) {
    if (!slot.thr && !slot.reset_wait)
      continue;
    Printf("  slot %u: reset_wait=%u/%u tid=%d pid=%d\n", (u32)slot.sid,
           slot.reset_wait,
           slot.thr ? atomic_load_relaxed(&slot.thr->reset_pending) : 0,
           slot.thr ? (int)slot.thr->tid : -1,
           slot.thr && slot.thr->tctx ? slot.thr->tctx->os_id : -1);
  }
}

namespace __tsan {

#if !SANITIZER_GO && !SANITIZER_MAC
__attribute__((tls_model("initial-exec")))
THREADLOCAL char cur_thread_placeholder[sizeof(ThreadState)] ALIGNED(64);
#endif
static char ctx_placeholder[sizeof(Context)] ALIGNED(64);
Context* ctx;

// Can be overriden by a front-end.
#ifdef TSAN_EXTERNAL_HOOKS
bool OnFinalize(bool failed);
void OnInitialize();
#else
SANITIZER_WEAK_CXX_DEFAULT_IMPL
bool OnFinalize(bool failed) {
#if !SANITIZER_GO
  if (__tsan_on_finalize)
    return reinterpret_cast<int (*)(int)>(__tsan_on_finalize)(failed);
#endif
  return failed;
}

SANITIZER_WEAK_CXX_DEFAULT_IMPL
void OnInitialize() {
#if !SANITIZER_GO
  if (__tsan_on_initialize)
    return reinterpret_cast<void (*)(void)>(__tsan_on_initialize)();
#endif
}
#endif

static TracePart* TracePartAlloc() {
  TracePart* part;
  {
    Lock l(&ctx->trace_part_mtx);
    //!!! we can affect the thread by resetting thr->trace_pos, but there are
    //!some events where we can't switch (under lock)
    // could we set something else that affects accesses/func entry/exit?
    //!!! when do we reset for real?
    if (ctx->trace_part_count > kMaxSid * 2)
      return nullptr;
    ctx->trace_part_count++;
    part = ctx->trace_part_cache;
    if (part)
      ctx->trace_part_cache = part->next;
  }
  if (!part)
    part = (TracePart*)MmapOrDie(sizeof(TracePart), "TracePart");
  part->next = nullptr;
  part->events[TracePart::kSize - 1] =
      NopEvent; //!!! how many do we need to initialize?
  return part;
}

static void TracePartFree(TracePart* part) {
  // Note: this runs only during reset when no other threads are running.
  // UnmapOrDie(part, sizeof(*part));
  part->next = ctx->trace_part_cache;
  ctx->trace_part_cache = part;
  CHECK_GT(ctx->trace_part_count, 0);
  ctx->trace_part_count--;
}

bool SlotUsable(TidSlot* slot) {
  DCHECK(!slot->thr);
  return slot->clock.Get(slot->sid) != kEpochLast;
}

void DoReset() {
  VPrintf(1, "ThreadSanitizer: global reset...\n");
  CHECK(!atomic_load_relaxed(&ctx->reset_pending));
  ctx->slot_mtx.CheckLocked();
  for (auto& slot : ctx->slots) {
    CHECK(!slot.thr);
    CHECK(!slot.reset_wait);
    slot.clock.Reset();
    for (TracePart* part = slot.trace.first; part;) {
      TracePart* next = part->next;
      TracePartFree(part);
      part = next;
    }
    slot.trace.first = slot.trace.current = nullptr;
    slot.trace.pos = nullptr;
    slot.trace.prev_pc = 0;
  }
  for (uptr i = 0; i < ARRAY_SIZE(ctx->slots); i++) {
    TidSlot* slot = &ctx->slots[i];
    CHECK(SlotUsable(slot));
    slot->prev = i ? &ctx->slots[i - 1] : nullptr;
    slot->next =
        i != (ARRAY_SIZE(ctx->slots) - 1) ? &ctx->slots[i + 1] : nullptr;
  }
  ctx->free_slot_head = &ctx->slots[0];
  ctx->free_slot_tail = &ctx->slots[ARRAY_SIZE(ctx->slots) - 1];
  DCHECK(SlotUsable(ctx->free_slot_head));

  DPrintf("Resetting shadow...\n");
  if (!MmapFixedNoReserve(ShadowBeg(), ShadowEnd() - ShadowBeg(), "shadow")) {
    Printf("failed to reset shadow memory\n");
    Die();
  }
  DPrintf("Resetting meta shadow...\n");
  ctx->metamap.Reset();
  {
    ThreadRegistryLock lock(&ctx->thread_registry);
    //!!! don't lock ThreadRegistry and do thread reset lazily?
    for (u32 i = ctx->thread_registry.NumThreadsLocked(); i--;) {
      ThreadContext* tctx =
          (ThreadContext*)ctx->thread_registry.GetThreadLocked(
              static_cast<Tid>(i));
      if (!tctx)
        continue;
      Free(tctx->sync);
      // Potentially we could purge all ThreadStatusDead threads from the
      // registry. Since we reset all shadow, they can't race with anything
      // anymore. However, their tid's can still be stored in some aux places
      // (e.g. tid of thread that created something).
      if (tctx->status != ThreadStatusRunning)
        continue;
      //!!! do this when the thread first attaches after reset
      ThreadState* thr = tctx->thr;
      CHECK(!thr->slot);
      thr->active = false;
      thr->last_slot = nullptr;
      atomic_store_relaxed(&thr->reset_pending, 0);
      thr->clock.Reset();
#if !SANITIZER_GO
      thr->last_sleep_stack_id = kInvalidStackID;
      thr->last_sleep_clock.Reset();
#endif
    }
  }
  /*
  DPrintf("Resuming threads...\n");
  for (u32 i = ctx->thread_registry.NumThreadsLocked(); i--;) {
    ThreadContext* tctx =
  (ThreadContext*)ctx->thread_registry.GetThreadLocked(static_cast<Tid>(i)); if
  (!tctx || !tctx->reset_wait) continue; CHECK_EQ(tctx->status,
  ThreadStatusRunning); tctx->reset_wait = false; tctx->reset_sema.Post();
  }
  */
}

void CompleteReset(ThreadState* thr) {
#if !SANITIZER_GO
  if (thr->in_symbolizer)
    return; //!!!
#endif
  ScopedRuntime rt(thr);
  SlotDetach(thr);
  SlotAttach(thr);
}

TidSlot* FindAttachSlotImpl(ThreadState* thr) {
  TidSlot* slot = thr->last_slot;
  if (!slot || slot->thr || !SlotUsable(slot))
    slot = ctx->free_slot_head;
  DPrintf2("#%d: FindAttachSlotImpl: found slot %d\n", thr->tid,
           slot ? (u32)slot->sid : -1);
  if (!slot)
    return nullptr;
  DCHECK(SlotUsable(slot));
  if (slot->next) {
    slot->next->prev = slot->prev;
  } else {
    DCHECK_EQ(slot, ctx->free_slot_tail);
    ctx->free_slot_tail = slot->prev;
  }
  if (slot->prev) {
    slot->prev->next = slot->next;
  } else {
    DCHECK_EQ(slot, ctx->free_slot_head);
    ctx->free_slot_head = slot->next;
  }
  slot->prev = slot->next = nullptr;
  DCHECK(slot != ctx->free_slot_head);
  if (ctx->free_slot_head && !SlotUsable(ctx->free_slot_head)) {
    Printf("XXX: slot=%d head=%u tail=%u\n", (u32)slot->sid,
           (u32)ctx->free_slot_head->sid, ctx->free_slot_tail->sid);
    DCHECK(!ctx->free_slot_head || SlotUsable(ctx->free_slot_head));
  }
  return slot;
}

bool InitTrace(Trace* trace) {
  if (!trace->first) {
    CHECK(!trace->pos);
    CHECK(!trace->prev_pc);
    TracePart* part = TracePartAlloc();
    if (!part)
      return false;
    trace->first = trace->current = part;
    trace->pos = &part->events[0];
    return true;
  }
  // Ensure we can trace at least slot attach.
  if (trace->pos + 1 >= &trace->current->events[TracePart::kSize]) {
    TracePart* part = TracePartAlloc();
    if (!part)
      return false;
    trace->current->next = part;
    trace->current = part;
    trace->pos = &part->events[0];
  }
  return true;
}

TidSlot& FindAttachSlot(ThreadState* thr) {
  CHECK(!thr->slot);
  int dump = -1;
  for (;;) {
    DPrintf2("#%d: FindAttachSlot: reset_pending=%d\n", thr->tid,
             atomic_load_relaxed(&ctx->reset_pending));
    if (!atomic_load_relaxed(&ctx->reset_pending)) {
      //!!! handle the case when all slots are busy, but not exhausted (>256
      //!threads), just wait
      TidSlot* slot = FindAttachSlotImpl(thr);
      //!!! if InitTrace fails we still can try other slots?
      if (slot && InitTrace(&slot->trace))
        return *slot;
      DPrintf("#%d: InitiateReset\n", thr->tid);
      int pending = 0;
      for (auto& slot : ctx->slots) {
        if (!slot.thr)
          continue;
        DPrintf("#%d: InitiateReset waiting for %d\n", thr->tid, slot.sid);
        CHECK(!slot.reset_wait);
        slot.reset_wait = true;
        pending++;
        ThreadPreempt(slot.thr);
      }
      if (!pending) {
        DoReset();
        continue;
      }
      dump = 50000;
      atomic_store_relaxed(&ctx->reset_pending, pending);
    }
    ctx->slot_mtx.Unlock();
    internal_usleep(100);
    if (dump && !--dump) {
      __tsan_dump();
#if !SANITIZER_GO
      for (auto& slot : ctx->slots) {
        if (!slot.thr && !slot.reset_wait)
          continue;
        slot.thr->unwind_abort = true;
        ThreadPreempt(slot.thr);
      }
      internal_usleep(5 * 1000 * 1000);
#endif
      Die();
    }
    ctx->slot_mtx.Lock();
  }
}

void SlotAttach(ThreadState* thr) {
  CheckNoLocks();
  {
    Lock lock(&ctx->slot_mtx);
    TidSlot& slot = FindAttachSlot(thr);
    DPrintf("#%d: SlotAttach: slot=%u\n", thr->tid, slot.sid);
    CHECK(!slot.thr);
    CHECK(!thr->slot);
    slot.thr = thr;
    thr->slot = &slot;
    thr->last_slot = &slot;
    //!!! skip acquire and increment if we we are attaching to the same slot
    Epoch epoch = EpochInc(slot.clock.Get(slot.sid));
    CHECK(!EpochOverflow(epoch));
    slot.clock.Set(slot.sid, epoch);
    //!!! is !thr->active can just copy the clock
    thr->clock.Acquire(&slot.clock);
    thr->fast_state.SetSid(slot.sid);
    thr->fast_state.SetEpoch(thr->clock.Get(slot.sid));
    CHECK(slot.trace.pos);
    atomic_store_relaxed(&thr->trace_pos, (uptr)slot.trace.pos);
    thr->trace_prev_pc = slot.trace.prev_pc;
    // While we cache trace data in thr, the data in the trace itself
    // is not up-to-date and should not be used.
    slot.trace.pos = nullptr;
    slot.trace.prev_pc = 0;
    if (!thr->active) {
      thr->active = true;
      thr->tctx->startMutexSet = thr->mset;
      thr->tctx->startStack.Init(thr->shadow_stack,
                                 thr->shadow_stack_pos - thr->shadow_stack);
    }
  }
  TraceSlotAttach(thr);
}

void SlotDetach(ThreadState* thr) {
  CheckNoLocks();
  Lock lock(&ctx->slot_mtx);
  CHECK(thr->slot);
  TidSlot* slot = thr->slot;
  CHECK_EQ(slot->thr, thr);
  DPrintf("#%d: SlotDetach: slot=%u\n", thr->tid, slot->sid);
  thr->slot = nullptr;
  slot->thr = nullptr;
  CHECK(!slot->next && !slot->prev);
  CHECK(!slot->reset_wait || atomic_load_relaxed(&ctx->reset_pending));
  slot->trace.pos = (Event*)atomic_load_relaxed(&thr->trace_pos);
  CHECK_LE(slot->trace.pos, &slot->trace.current->events[TracePart::kSize]);
  slot->trace.prev_pc = thr->trace_prev_pc;
  atomic_store_relaxed(&thr->trace_pos, 0);
  thr->trace_prev_pc = 0;
  slot->clock = thr->clock; //!!! could make this lazy
  CHECK(!slot->next && !slot->prev);
  if (SlotUsable(slot)) {
    TidSlot* tail = ctx->free_slot_tail;
    if (tail) {
      tail->next = slot;
      slot->prev = tail;
    } else {
      CHECK(!ctx->free_slot_head);
      ctx->free_slot_head = slot;
    }
    ctx->free_slot_tail = slot;
  }
  DCHECK(!ctx->free_slot_head || SlotUsable(ctx->free_slot_head));
  if (slot->reset_wait) {
    slot->reset_wait = false;
    int pending = atomic_load_relaxed(&ctx->reset_pending) - 1;
    DPrintf("#%d: CompleteReset: pending=%d\n", thr->tid, pending);
    CHECK_GE(pending, 0);
    atomic_store_relaxed(&ctx->reset_pending, pending);
    if (!pending)
      DoReset();
  }
}

Context::Context()
    : initialized(), report_mtx(MutexTypeReport), nreported(),
      nmissed_expected(), thread_registry([](Tid tid) -> ThreadContextBase* {
        return new (Alloc(sizeof(ThreadContext))) ThreadContext(tid);
      }),
      racy_mtx(MutexTypeRacy), racy_stacks(), racy_addresses(),
      fired_suppressions_mtx(MutexTypeFired), slot_mtx(MutexTypeSlot),
      trace_part_mtx(MutexTypeTraceAlloc) {
  fired_suppressions.reserve(8);
  for (uptr i = 0; i < ARRAY_SIZE(slots); i++) {
    TidSlot* slot = &slots[i];
    slot->sid = static_cast<Sid>(i);
    slot->prev = i ? &slots[i - 1] : nullptr;
    slot->next = i != (ARRAY_SIZE(slots) - 1) ? &slots[i + 1] : nullptr;
  }
  free_slot_head = &slots[0];
  free_slot_tail = &slots[ARRAY_SIZE(slots) - 1];
}

// The objects are allocated in TLS, so one may rely on zero-initialization.
ThreadState::ThreadState(Tid tid)
    // Do not touch these, rely on zero initialization,
    // they may be accessed before the ctor.
    // ignore_reads_and_writes()
    // ignore_interceptors()
    : tid(tid) {
#if !SANITIZER_GO
  shadow_stack_pos = shadow_stack;
  shadow_stack_end = shadow_stack + kShadowStackSize;
#else
  // Setup dynamic shadow stack.
  const int kInitStackSize = 8;
  shadow_stack = (uptr*)Alloc(kInitStackSize * sizeof(uptr));
  shadow_stack_pos = shadow_stack;
  shadow_stack_end = shadow_stack + kInitStackSize;
#endif
}

#if !SANITIZER_GO
#  if 0
static void MemoryProfiler(Context* ctx, fd_t fd, int i) {
  uptr n_threads;
  uptr n_running_threads;
  ctx->thread_registry.GetNumberOfThreads(&n_threads, &n_running_threads);
  InternalMmapVector<char> buf(4096);
  WriteMemoryProfile(buf.data(), buf.size(), n_threads, n_running_threads);
  WriteToFile(fd, buf.data(), internal_strlen(buf.data()));
}

static void* BackgroundThread(void* arg) {
  // This is a non-initialized non-user thread, nothing to see here.
  // We don't use ScopedIgnoreInterceptors, because we want ignores to be
  // enabled even when the thread function exits (e.g. during pthread thread
  // shutdown code).
  cur_thread_init();
  cur_thread()->ignore_interceptors++;
  const u64 kMs2Ns = 1000 * 1000;

  fd_t mprof_fd = kInvalidFd;
  if (flags()->profile_memory && flags()->profile_memory[0]) {
    if (internal_strcmp(flags()->profile_memory, "stdout") == 0) {
      mprof_fd = 1;
    } else if (internal_strcmp(flags()->profile_memory, "stderr") == 0) {
      mprof_fd = 2;
    } else {
      InternalScopedString filename;
      filename.append("%s.%d", flags()->profile_memory, (int)internal_getpid());
      fd_t fd = OpenFile(filename.data(), WrOnly);
      if (fd == kInvalidFd) {
        Printf("ThreadSanitizer: failed to open memory profile file '%s'\n",
               filename.data());
      } else {
        mprof_fd = fd;
      }
    }
  }

  u64 last_flush = NanoTime();
  uptr last_rss = 0;
  for (int i = 0;
       atomic_load(&ctx->stop_background_thread, memory_order_relaxed) == 0;
       i++) {
    internal_usleep(100*1000);
    u64 now = NanoTime();

    // Flush memory if requested.
    if (flags()->flush_memory_ms > 0) {
      if (last_flush + flags()->flush_memory_ms * kMs2Ns < now) {
        VPrintf(1, "ThreadSanitizer: periodic memory flush\n");
        FlushShadowMemory();
        last_flush = NanoTime();
      }
    }
    // GetRSS can be expensive on huge programs, so don't do it every 100ms.
    if (flags()->memory_limit_mb > 0) {
      uptr rss = GetRSS();
      uptr limit = uptr(flags()->memory_limit_mb) << 20;
      VPrintf(1,
              "ThreadSanitizer: memory flush check"
              " RSS=%llu LAST=%llu LIMIT=%llu\n",
              (u64)rss >> 20, (u64)last_rss >> 20, (u64)limit >> 20);
      if (2 * rss > limit + last_rss) {
        VPrintf(1, "ThreadSanitizer: flushing memory due to RSS\n");
        FlushShadowMemory();
        rss = GetRSS();
        VPrintf(1, "ThreadSanitizer: memory flushed RSS=%llu\n",
                (u64)rss >> 20);
      }
      last_rss = rss;
    }

    // Write memory profile if requested.
    if (mprof_fd != kInvalidFd)
      MemoryProfiler(ctx, mprof_fd, i);

    // Flush symbolizer cache if requested.
    if (flags()->flush_symbolizer_ms > 0) {
      u64 last =
          atomic_load(&ctx->last_symbolize_time_ns, memory_order_relaxed);
      if (last != 0 && last + flags()->flush_symbolizer_ms * kMs2Ns < now) {
        Lock l(&ctx->report_mtx);
        ScopedErrorReportLock l2;
        SymbolizerFlush();
        atomic_store(&ctx->last_symbolize_time_ns, 0, memory_order_relaxed);
      }
    }
  }
  return nullptr;
}
#  endif

static void StartBackgroundThread() {
  //!!! do we still need the background thread?
  // ctx->background_thread = internal_start_thread(&BackgroundThread, 0);
}

#ifndef __mips__
static void StopBackgroundThread() {
  // atomic_store(&ctx->stop_background_thread, 1, memory_order_relaxed);
  // internal_join_thread(ctx->background_thread);
  // ctx->background_thread = 0;
}
#endif
#endif

void DontNeedShadowFor(uptr addr, uptr size) {
  ReleaseMemoryPagesToOS(MemToShadow(addr), MemToShadow(addr + size));
}

#if !SANITIZER_GO
void UnmapShadow(ThreadState* thr, uptr addr, uptr size) {
  if (size == 0)
    return;
  DontNeedShadowFor(addr, size);
  ScopedGlobalProcessor sgp;
  ScopedRuntime rt(thr);
  ctx->metamap.ResetRange(thr->proc(), addr, size);
}
#endif

void MapShadow(uptr addr, uptr size) {
  // Global data is not 64K aligned, but there are no adjacent mappings,
  // so we can get away with unaligned mapping.
  // CHECK_EQ(addr, addr & ~((64 << 10) - 1));  // windows wants 64K alignment
  const uptr kPageSize = GetPageSizeCached();
  uptr shadow_begin = RoundDownTo((uptr)MemToShadow(addr), kPageSize);
  uptr shadow_end = RoundUpTo((uptr)MemToShadow(addr + size), kPageSize);
  if (!MmapFixedSuperNoReserve(shadow_begin, shadow_end - shadow_begin,
                               "shadow"))
    Die();

  // Meta shadow is 2:1, so tread carefully.
  static bool data_mapped = false;
  static uptr mapped_meta_end = 0;
  uptr meta_begin = (uptr)MemToMeta(addr);
  uptr meta_end = (uptr)MemToMeta(addr + size);
  meta_begin = RoundDownTo(meta_begin, 64 << 10);
  meta_end = RoundUpTo(meta_end, 64 << 10);
  if (!data_mapped) {
    // First call maps data+bss.
    data_mapped = true;
    if (!MmapFixedSuperNoReserve(meta_begin, meta_end - meta_begin,
                                 "meta shadow"))
      Die();
  } else {
    // Mapping continous heap.
    // Windows wants 64K alignment.
    meta_begin = RoundDownTo(meta_begin, 64 << 10);
    meta_end = RoundUpTo(meta_end, 64 << 10);
    if (meta_end <= mapped_meta_end)
      return;
    if (meta_begin < mapped_meta_end)
      meta_begin = mapped_meta_end;
    if (!MmapFixedSuperNoReserve(meta_begin, meta_end - meta_begin,
                                 "meta shadow"))
      Die();
    mapped_meta_end = meta_end;
  }
  VPrintf(2, "mapped meta shadow for (%p-%p) at (%p-%p)\n", addr, addr + size,
          meta_begin, meta_end);
}

static void CheckShadowMapping() {
  uptr beg, end;
  for (int i = 0; GetUserRegion(i, &beg, &end); i++) {
    // Skip cases for empty regions (heap definition for architectures that
    // do not use 64-bit allocator).
    if (beg == end)
      continue;
    VPrintf(3, "checking shadow region %p-%p\n", beg, end);
    uptr prev = 0;
    for (uptr p0 = beg; p0 <= end; p0 += (end - beg) / 4) {
      for (int x = -(int)kShadowCell; x <= (int)kShadowCell; x += kShadowCell) {
        const uptr p = RoundDown(p0 + x, kShadowCell);
        if (p < beg || p >= end)
          continue;
        const uptr s = MemToShadow(p);
        const uptr m = (uptr)MemToMeta(p);
        VPrintf(3, "  checking pointer %p: shadow=%p meta=%p\n", p, s, m);
        CHECK(IsAppMem(p));
        CHECK(IsShadowMem(s));
        CHECK_EQ(p, ShadowToMem(s));
        CHECK(IsMetaMem(m));
        if (prev) {
          // Ensure that shadow and meta mappings are linear within a single
          // user range. Lots of code that processes memory ranges assumes it.
          const uptr prev_s = MemToShadow(prev);
          const uptr prev_m = (uptr)MemToMeta(prev);
          CHECK_EQ(s - prev_s, (p - prev) * kShadowMultiplier);
          CHECK_EQ((m - prev_m) / kMetaShadowSize,
                   (p - prev) / kMetaShadowCell);
        }
        prev = p;
      }
    }
  }
}

#if !SANITIZER_GO
static void OnStackUnwind(const SignalContext& sig, const void*,
                          BufferedStackTrace* stack) {
  stack->Unwind(StackTrace::GetNextInstructionPc(sig.pc), sig.bp, sig.context,
                common_flags()->fast_unwind_on_fatal);
}

static void TsanOnDeadlySignal(int signo, void* siginfo, void* context) {
  HandleDeadlySignal(siginfo, context, static_cast<Tid>(GetTid()),
                     &OnStackUnwind, nullptr);
}
#endif

void CheckUnwind() {
  // There is high probability that interceptors will check-fail as well,
  // on the other hand there is no sense in processing interceptors
  // since we are going to die soon.
  ScopedIgnoreInterceptors ignore;
#if !SANITIZER_GO
  cur_thread()->nomalloc = false;
  cur_thread()->ignore_sync++;
  cur_thread()->ignore_reads_and_writes++;
#endif
  PrintCurrentStackSlow(StackTrace::GetCurrentPc());
  Printf("\n");
  __tsan_dump(); //!!!
}

void Initialize(ThreadState *thr) {
  // Thread safe because done before all threads exist.
  static bool is_initialized = false;
  if (is_initialized)
    return;
  is_initialized = true;
  // We are not ready to handle interceptors yet.
  ScopedIgnoreInterceptors ignore;
  SanitizerToolName = "ThreadSanitizer";
  // Install tool-specific callbacks in sanitizer_common.
  SetCheckUnwindCallback(CheckUnwind);

  ctx = new (ctx_placeholder) Context;
  const char* env_name = SANITIZER_GO ? "GORACE" : "TSAN_OPTIONS";
  const char* options = GetEnv(env_name);
  CacheBinaryName();
  CheckASLR();
  InitializeFlags(&ctx->flags, options, env_name);
  AvoidCVE_2016_2143();
  __sanitizer::InitializePlatformEarly();
  __tsan::InitializePlatformEarly();

#if !SANITIZER_GO
  // Re-exec ourselves if we need to set additional env or command line args.
  MaybeReexec();

  InitializeAllocator();
  ReplaceSystemMalloc();
#endif
  if (common_flags()->detect_deadlocks)
    ctx->dd = DDetector::Create(flags());
  Processor* proc = ProcCreate();
  ProcWire(proc, thr);
  InitializeInterceptors();
  CheckShadowMapping();
  InitializePlatform();
  InitializeMutex();
  InitializeDynamicAnnotations();
#if !SANITIZER_GO
  InitializeShadowMemory();
  InitializeAllocatorLate();
  InstallDeadlySignalHandlers(TsanOnDeadlySignal);
#endif
  // Setup correct file descriptor for error reports.
  __sanitizer_set_report_path(common_flags()->log_path);
  InitializeSuppressions();
#if !SANITIZER_GO
  InitializeLibIgnore();
#endif

  VPrintf(1, "***** Running under ThreadSanitizer v3 (pid %d) *****\n",
          (int)internal_getpid());

  // Initialize thread 0.
  Tid tid = ThreadCreate(nullptr, 0, 0, true);
  CHECK_EQ(tid, 0);
  ThreadStart(thr, tid, GetTid(), ThreadType::Regular);
#if TSAN_CONTAINS_UBSAN
  __ubsan::InitAsPlugin();
#endif
  ctx->initialized = true;

#if !SANITIZER_GO
  Symbolizer::LateInitialize();
#endif

  Shadow ro(0);
  ro.SetAccess(0, kSizeLog1, true, false, false);
  CHECK_EQ(ro.raw(), Shadow::kShadowRodata);

  if (flags()->stop_on_start) {
    Printf("ThreadSanitizer is suspended at startup (pid %d)."
           " Call __tsan_resume().\n",
           (int)internal_getpid());
    while (__tsan_resumed == 0) {
    }
  }

  OnInitialize();
}

void MaybeSpawnBackgroundThread() {
  // On MIPS, TSan initialization is run before
  // __pthread_initialize_minimal_internal() is finished, so we can not spawn
  // new threads.
#if !SANITIZER_GO && !defined(__mips__)
  static atomic_uint32_t bg_thread = {};
  if (atomic_load(&bg_thread, memory_order_relaxed) == 0 &&
      atomic_exchange(&bg_thread, 1, memory_order_relaxed) == 0) {
    StartBackgroundThread();
    SetSandboxingCallback(StopBackgroundThread);
  }
#endif
}

int Finalize(ThreadState* thr) {
  bool failed = false;

  if (common_flags()->print_module_map == 1)
    DumpProcessMap();

  if (flags()->atexit_sleep_ms > 0 && ThreadCount(thr) > 1)
    internal_usleep(u64(flags()->atexit_sleep_ms) * 1000);

  {
    // Wait for pending reports.
    ScopedRuntime rt(thr);
    Lock lock1(&ctx->report_mtx);
    ScopedErrorReportLock lock2;
  }

#if !SANITIZER_GO
  if (Verbosity())
    AllocatorPrintStats();
#endif

  ThreadFinalize(thr);

  if (ctx->nreported) {
    failed = true;
#if !SANITIZER_GO
    Printf("ThreadSanitizer: reported %d warnings\n", ctx->nreported);
#else
    Printf("Found %d data race(s)\n", ctx->nreported);
#endif
  }

  if (ctx->nmissed_expected) {
    failed = true;
    Printf("ThreadSanitizer: missed %d expected races\n",
           ctx->nmissed_expected);
  }

  if (common_flags()->print_suppressions)
    PrintMatchedSuppressions();

  failed = OnFinalize(failed);

#if TSAN_COLLECT_STATS
  StatAggregate(ctx->stat, thr->stat);
  StatOutput(ctx->stat);
#endif

  return failed ? common_flags()->exitcode : 0;
}

#if !SANITIZER_GO
void ForkBefore(ThreadState* thr, uptr pc) {
  ScopedRuntime::Enter(thr);
  ctx->slot_mtx.Lock();
  ctx->thread_registry.Lock();
  ctx->report_mtx.Lock();
  // Suppress all reports in the pthread_atfork callbacks.
  // Reports will deadlock on the report_mtx.
  // We could ignore interceptors and sync operations as well,
  // but so far it's unclear if it will do more good or harm.
  // Unnecessarily ignoring things can lead to false positives later.
  thr->suppress_reports++;
}

void ForkParentAfter(ThreadState *thr, uptr pc) {
  thr->suppress_reports--;  // Enabled in ForkBefore.
  ctx->report_mtx.Unlock();
  ctx->thread_registry.Unlock();
  ctx->slot_mtx.Unlock();
  ScopedRuntime::Leave(thr);
}

void ForkChildAfter(ThreadState *thr, uptr pc) {
  thr->suppress_reports--;  // Enabled in ForkBefore.
  ctx->report_mtx.Unlock();
  ctx->thread_registry.Unlock();
  ctx->slot_mtx.Unlock();

  uptr nthread = 0;
  ctx->thread_registry.GetNumberOfThreads(0, 0, &nthread /* alive threads */);
  VPrintf(1,
          "ThreadSanitizer: forked new process with pid %d,"
          " parent had %d threads\n",
          (int)internal_getpid(), (int)nthread);
  if (nthread == 1) {
    StartBackgroundThread();
  } else {
    // We've just forked a multi-threaded process. We cannot reasonably function
    // after that (some mutexes may be locked before fork). So just enable
    // ignores for everything in the hope that we will exec soon.
    ctx->after_multithreaded_fork = true;
    thr->ignore_interceptors++;
    ThreadIgnoreBegin(thr, pc);
    ThreadIgnoreSyncBegin(thr, pc);
  }
  ScopedRuntime::Leave(thr);
}
#endif

#if SANITIZER_GO
NOINLINE
void GrowShadowStack(ThreadState* thr) {
  const int sz = thr->shadow_stack_end - thr->shadow_stack;
  const int newsz = 2 * sz;
  uptr* newstack = (uptr*)Alloc(newsz * sizeof(uptr));
  internal_memcpy(newstack, thr->shadow_stack, sz * sizeof(uptr));
  Free(thr->shadow_stack);
  thr->shadow_stack = newstack;
  thr->shadow_stack_pos = newstack + sz;
  thr->shadow_stack_end = newstack + newsz;
}
#endif

StackID CurrentStackId(ThreadState* thr, uptr pc) {
#if !SANITIZER_GO
  if (!thr->is_inited) // May happen during bootstrap.
    return kInvalidStackID;
#endif
  if (pc != 0) {
#if !SANITIZER_GO
    DCHECK_LT(thr->shadow_stack_pos, thr->shadow_stack_end);
#else
    if (thr->shadow_stack_pos == thr->shadow_stack_end)
      GrowShadowStack(thr);
#endif
    thr->shadow_stack_pos[0] = pc;
    thr->shadow_stack_pos++;
  }
  StackID id = StackDepotPut(
      StackTrace(thr->shadow_stack, thr->shadow_stack_pos - thr->shadow_stack));
  if (pc != 0)
    thr->shadow_stack_pos--;
  return id;
}

NOINLINE
void TraceSwitch(ThreadState* thr) {
  CHECK(atomic_load_relaxed(&thr->in_runtime));
  auto part = thr->slot->trace.current;
  Event* pos = (Event*)atomic_load_relaxed(&thr->trace_pos);
  Event* end = &part->events[TracePart::kSize];
  //!!! can't return due to event restart
  // we either need to remove false positive switches, or store some fake 0
  // event in this position
  if (pos + 1 < end)
    return;
#if !SANITIZER_GO
  // !!! can we still do this? should we at least rewind pos to beginning of
  // part?
  if (ctx->after_multithreaded_fork)
    return;
#endif
  // Comment for this:
  // tsan: do not call malloc/free in memory access handling routine.
  // This improves signal-/fork-safety of instrumented programs.
  // Date:   Fri Jun 22 11:08:55 2012 +0000
  //!!! thr->nomalloc++;
  part = TracePartAlloc();
  if (!part) {
    SlotDetach(thr);
    SlotAttach(thr);
    return;
  }
  Lock lock(&thr->slot->trace.mtx);
  thr->slot->trace.current->next = part;
  thr->slot->trace.current = part;
  thr->slot->trace.pos = 0;
  atomic_store_relaxed(&thr->trace_pos, (uptr)&part->events[0]);
  // thr->nomalloc--;
}

ALWAYS_INLINE Shadow LoadShadow(RawShadow* p) {
  return Shadow(atomic_load((atomic_uint32_t*)p, memory_order_relaxed));
}

ALWAYS_INLINE void StoreShadow(RawShadow* sp, RawShadow s) {
  atomic_store((atomic_uint32_t*)sp, s, memory_order_relaxed);
}

ALWAYS_INLINE
void StoreAndZero(RawShadow* sp, RawShadow* s) {
  StoreShadow(sp, *s);
  // *s = 0;
}

ALWAYS_INLINE
bool HappensBefore(Shadow old, ThreadState* thr) {
  return thr->clock.Get(old.sid()) >= old.epoch();
}

ALWAYS_INLINE
void MemoryAccessImpl1(ThreadState* thr, uptr addr, u32 kAccessSizeLog,
                       bool kAccessIsWrite, bool kIsAtomic,
                       RawShadow* shadow_mem, Shadow cur) {
  CHECK(atomic_load_relaxed(&thr->in_runtime)); //!!!
  StatInc(thr, StatMop);
  StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
  StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));

  // scan all the shadow values and dispatch to 4 categories:
  // same, replace, candidate and race (see comments below).
  // we consider only 3 cases regarding access sizes:
  // equal, intersect and not intersect. initially I considered
  // larger and smaller as well, it allowed to replace some
  // 'candidates' with 'same' or 'replace', but I think
  // it's just not worth it (performance- and complexity-wise).

  bool stored = false;
  Shadow old(0);

#if SANITIZER_DEBUG
  for (int idx = 0; idx < 4; idx++) {
#include "tsan_update_shadow_word_inl.h"
  }
#else
  int idx = 0;
#include "tsan_update_shadow_word_inl.h"
  idx = 1;
#include "tsan_update_shadow_word_inl.h"
  idx = 2;
#include "tsan_update_shadow_word_inl.h"
  idx = 3;
#include "tsan_update_shadow_word_inl.h"
#endif

  // We did not find any races and had already stored
  // the current access info, so we are done.
  if (LIKELY(stored))
    return;
  {
    // Choose a random candidate slot and replace it.
    uptr index = static_cast<uptr>(cur.epoch()) %
                 kShadowCnt; //!!! very low entropy, epoch does not change often
    StoreShadow(&shadow_mem[index], cur.raw());
    StatInc(thr, StatShadowReplace);
  }
  return;
RACE:
  ReportRace(thr, shadow_mem, cur, old);
}

void UnalignedMemoryAccess(ThreadState* thr, uptr pc, uptr addr, int size,
                           bool kAccessIsWrite, bool kIsAtomic) {
  CHECK(atomic_load_relaxed(&thr->in_runtime)); //!!!
  while (size) {
    int size1 = 1;
    int kAccessSizeLog = kSizeLog1;
    if (size >= 8 && (addr & ~7) == ((addr + 7) & ~7)) {
      size1 = 8;
      kAccessSizeLog = kSizeLog8;
    } else if (size >= 4 && (addr & ~7) == ((addr + 3) & ~7)) {
      size1 = 4;
      kAccessSizeLog = kSizeLog4;
    } else if (size >= 2 && (addr & ~7) == ((addr + 1) & ~7)) {
      size1 = 2;
      kAccessSizeLog = kSizeLog2;
    }
    MemoryAccess(thr, pc, addr, kAccessSizeLog, kAccessIsWrite, kIsAtomic);
    addr += size1;
    size -= size1;
  }
}

ALWAYS_INLINE
bool ContainsSameAccessSlow(RawShadow* s, RawShadow a, bool isRead) {
  Shadow cur(a);
  for (uptr i = 0; i < kShadowCnt; i++) {
    Shadow old(LoadShadow(&s[i]));
    if (isRead && old.raw() == Shadow::kShadowRodata)
      return true;
    //!!! speed up, this is used at least for Go.
    if (Shadow::AddrSizeEqualNotFreed(cur, old) && old.sid() == cur.sid() &&
        old.epoch() == cur.epoch() && old.IsAtomic() == cur.IsAtomic() &&
        old.IsRead() <= cur.IsRead())
      return true;
  }
  return false;
}

#if defined(__SSE3__)
ALWAYS_INLINE
bool ContainsSameAccessFast(RawShadow* s, RawShadow a, bool isRead) {
  // This is an optimized version of ContainsSameAccessSlow.
  const m128 access = _mm_set1_epi32(a);
  const m128 shadow = _mm_load_si128((m128*)s);
  if (isRead) {
    // For reads we need to reset read bit in the shadow,
    // because we need to match read with both reads and writes.
    // kShadowRodata has only read bit set, so it does what we want.
    // We also abuse it for rodata check to save few cycles
    // since we already loaded kShadowRodata into a register.
    // Reads from rodata can't race.
    // Measurements show that they can be 10-20% of all memory accesses.
    // kShadowRodata has epoch 0 which cannot appear in shadow normally
    // (thread epochs start from 1). So the same read bit mask
    // serves as rodata indicator.
    // Access to .rodata section, no races here.
    const m128 read_mask = _mm_set1_epi32(Shadow::kShadowRodata);
    //!!! we can also skip it for range memory access, they already checked
    //!rodata.
#  if !SANITIZER_GO
    const m128 ro = _mm_cmpeq_epi32(shadow, read_mask);
#  endif
    const m128 masked_shadow = _mm_or_si128(shadow, read_mask);
    const m128 same = _mm_cmpeq_epi32(masked_shadow, access);
#  if !SANITIZER_GO
    const m128 res = _mm_or_si128(ro, same);
    return _mm_movemask_epi8(res);
#  else
    return _mm_movemask_epi8(same);
#  endif
  }
  const m128 same = _mm_cmpeq_epi32(shadow, access);
  return _mm_movemask_epi8(same);
}
#endif

ALWAYS_INLINE
bool ContainsSameAccess(RawShadow* s, RawShadow a, bool isRead) {
#if defined(__SSE3__)
  bool res = ContainsSameAccessFast(s, a, isRead);
  // NOTE: this check can fail if the shadow is concurrently mutated
  // by other threads. But it still can be useful if you modify
  // ContainsSameAccessFast and want to ensure that it's not completely broken.
  // DCHECK_EQ(res, ContainsSameAccessSlow(s, a, isRead));
  return res;
#else
  return ContainsSameAccessSlow(s, a, isRead);
#endif
}

char* DumpShadow(char* buf, RawShadow raw) {
  if (raw == 0) {
    internal_snprintf(buf, 64, "0");
    return buf;
  }
  Shadow s(raw);
  internal_snprintf(buf, 64, "{tid=%u@%u access=0x%x type=%u/%u/%u}",
                    static_cast<u32>(s.sid()), static_cast<u32>(s.epoch()),
                    s.access(), s.IsRead(), s.IsAtomic(), s.IsFreed());
  return buf;
}

ALWAYS_INLINE WARN_UNUSED_RESULT bool
TraceMemoryAccess(ThreadState* thr, uptr pc, uptr addr, uptr sizeLog,
                  bool isRead, bool isAtomic) {
  if (!kCollectHistory)
    return true;
  EventAccess* ev;
  if (!TraceAcquire(thr, &ev))
    return false;
  uptr pcDelta = pc - thr->trace_prev_pc + (1 << 14);
  thr->trace_prev_pc = pc;
  if (LIKELY(pcDelta < (1 << 15))) {
    ev->isAccess = 1; //!!! if we use 0, does it make code more efficient?
    ev->isRead = isRead;
    ev->isAtomic = isAtomic;
    ev->isExternalPC = 0; //!!!
    ev->sizeLog = sizeLog;
    ev->pcDelta = pcDelta;
    DCHECK_EQ(ev->pcDelta, pcDelta);
    ev->addr = addr;
    TraceRelease(thr, ev);
    return true;
  }
  auto evex = reinterpret_cast<EventAccessEx*>(ev);
  evex->isAccess = 0;
  evex->type = EventTypeAccessEx;
  evex->isRead = isRead;
  evex->isAtomic = isAtomic;
  evex->isFreed = 0;
  evex->isExternalPC = 0; //!!!
  evex->sizeLo = 1 << sizeLog;
  evex->pc = pc;
  evex->isNotAccess = 0;
  evex->addr = addr;
  evex->sizeHi = 0;
  TraceRelease(thr, evex);
  return true;
}

template <bool kInRuntime>
NOINLINE void TraceRestartMemoryAccess(ThreadState* thr, uptr pc, uptr addr,
                                       u32 kAccessSizeLog, bool kAccessIsWrite,
                                       bool kIsAtomic) {
  MaybeScopedRuntime<kInRuntime> rt(thr);
  TraceSwitch(thr);
  MemoryAccess(thr, pc, addr, kAccessSizeLog, kAccessIsWrite, kIsAtomic);
}

static NOINLINE void ReportRaceV(ThreadState* thr, RawShadow* shadow_mem,
                                 Shadow cur, u32 race_mask, m128 shadow) {
  CHECK_NE(race_mask, 0);
  u32 old;
  switch (__builtin_ffs(race_mask) / 4) {
  case 0:
    old = _mm_extract_epi32(shadow, 0);
    break;
  case 1:
    old = _mm_extract_epi32(shadow, 1);
    break;
  case 2:
    old = _mm_extract_epi32(shadow, 2);
    break;
  case 3:
    old = _mm_extract_epi32(shadow, 3);
    break;
  }
  ReportRace(thr, shadow_mem, cur, Shadow(old));
}

template <bool kInRuntime>
ALWAYS_INLINE USED void
MemoryAccess(ThreadState* thr, uptr pc, uptr addr, u32 kAccessSizeLog,
             bool kAccessIsWrite, //!!! change all kAccessIsWrite to isRead
             bool kIsAtomic) {
  DCHECK_EQ(kInRuntime, atomic_load_relaxed(&thr->in_runtime));
  RawShadow* shadow_mem = (RawShadow*)MemToShadow(addr);
  char memBuf[4][64];
  (void)memBuf;
  DPrintf2("#%d: Access: @%p %p size=%d"
           " is_write=%d shadow=%p {%s, %s, %s, %s}\n",
           (int)thr->tid, (void*)pc, (void*)addr, (int)(1 << kAccessSizeLog),
           kAccessIsWrite, shadow_mem, DumpShadow(memBuf[0], shadow_mem[0]),
           DumpShadow(memBuf[1], shadow_mem[1]),
           DumpShadow(memBuf[2], shadow_mem[2]),
           DumpShadow(memBuf[3], shadow_mem[3]));
#if SANITIZER_DEBUG
  if (!IsAppMem(addr)) {
    Printf("Access to non app mem %zx\n", addr);
    DCHECK(IsAppMem(addr));
  }
  if (!IsShadowMem((uptr)shadow_mem)) {
    Printf("Bad shadow addr %p (%zx)\n", shadow_mem, addr);
    DCHECK(IsShadowMem((uptr)shadow_mem));
  }
#endif

  Shadow cur(thr->fast_state);
  cur.SetAccess(addr, kAccessSizeLog, !kAccessIsWrite, kIsAtomic, false);
  // cur.SetAddr0AndSizeLog(addr & 7, kAccessSizeLog);
  // cur.SetWrite(kAccessIsWrite);
  // cur.SetAtomic(kIsAtomic);

  // This is an optimized version of ContainsSameAccessSlow.
  const m128 access = _mm_set1_epi32(cur.raw());
  const m128 shadow = _mm_load_si128((m128*)shadow_mem);
  DPrintf2("  MOP: shadow=%V access=%V\n", shadow, access);

  bool same_access;
  if (kAccessIsWrite) {
    const m128 same = _mm_cmpeq_epi32(shadow, access);
    same_access = _mm_movemask_epi8(same);
  } else {
    // For reads we need to reset read bit in the shadow,
    // because we need to match read with both reads and writes.
    // kShadowRodata has only read bit set, so it does what we want.
    // We also abuse it for rodata check to save few cycles
    // since we already loaded kShadowRodata into a register.
    // Reads from rodata can't race.
    // Measurements show that they can be 10-20% of all memory accesses.
    // kShadowRodata has epoch 0 which cannot appear in shadow normally
    // (thread epochs start from 1). So the same read bit mask
    // serves as rodata indicator.
    // Access to .rodata section, no races here.
    const m128 read_mask = _mm_set1_epi32(Shadow::kShadowRodata);
    //!!! we can also skip it for range memory access, they already checked
    //!rodata.
#if !SANITIZER_GO
    const m128 ro = _mm_cmpeq_epi32(shadow, read_mask);
#endif
    const m128 masked_shadow = _mm_or_si128(shadow, read_mask);
    const m128 same = _mm_cmpeq_epi32(masked_shadow, access);
#if !SANITIZER_GO
    const m128 res = _mm_or_si128(ro, same);
    same_access = _mm_movemask_epi8(res);
#else
    same_access = _mm_movemask_epi8(same);
#endif
  }
  if (LIKELY(same_access))
    return;

  if (UNLIKELY(thr->ignore_enabled_)) {
    StatInc(thr, StatMop);
    StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
    StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));
    StatInc(thr, StatMopIgnored);
    return;
  }

  //!!! we could move this below since we store at a single point now
  if (!TraceMemoryAccess(thr, pc, addr, kAccessSizeLog, !kAccessIsWrite,
                         kIsAtomic))
    return TraceRestartMemoryAccess<kInRuntime>(thr, pc, addr, kAccessSizeLog,
                                                kAccessIsWrite, kIsAtomic);

  //!!! handle is freed

  const m128 zero = _mm_setzero_si128();
  const m128 mask_access = _mm_set1_epi32(0x000000ff);
  const m128 mask_sid = _mm_set1_epi32(0x0000ff00);
  const m128 mask_access_sid = _mm_set1_epi32(0x0000ffff);
  const m128 mask_read_atomic = _mm_set1_epi32(0xc0000000);
  const m128 access_and = _mm_and_si128(access, shadow);
  const m128 access_xor = _mm_xor_si128(access, shadow);
  //!!! can we and intersect+not_same_sid and then negate once?
  const m128 intersect = _mm_and_si128(access_and, mask_access);
  const m128 not_intersect = _mm_cmpeq_epi32(intersect, zero);
  const m128 not_same_sid = _mm_and_si128(access_xor, mask_sid);
  const m128 same_sid = _mm_cmpeq_epi32(not_same_sid, zero);
  const m128 both_read_or_atomic = _mm_and_si128(access_and, mask_read_atomic);
  const m128 no_race =
      _mm_or_si128(_mm_or_si128(not_intersect, same_sid), both_read_or_atomic);
  const int race_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(no_race, zero));
  DPrintf2("  MOP: not_intersect=%V same_sid=%V both_read_or_atomic=%V "
           "race_mask=%04x\n",
           not_intersect, same_sid, both_read_or_atomic, race_mask);
  if (UNLIKELY(race_mask))
    goto SHARED;

STORE : {
  const m128 not_same_sid_access = _mm_and_si128(access_xor, mask_access_sid);
  const m128 same_sid_access = _mm_cmpeq_epi32(not_same_sid_access, zero);
  const m128 access_read_atomic =
      _mm_set1_epi32(((u32)kIsAtomic << 31) | ((kAccessIsWrite ^ 1) << 30));
  const m128 rw_weaker =
      _mm_cmpeq_epi32(_mm_max_epu32(shadow, access_read_atomic), shadow);
  const m128 rewrite = _mm_and_si128(same_sid_access, rw_weaker);
  const int rewrite_mask = _mm_movemask_epi8(rewrite);
  int index = __builtin_ffs(rewrite_mask);
  if (UNLIKELY(index == 0)) {
    const m128 empty = _mm_cmpeq_epi32(shadow, zero);
    const int empty_mask = _mm_movemask_epi8(empty);
    index = __builtin_ffs(empty_mask);
    if (UNLIKELY(index == 0))
      index = (atomic_load_relaxed(&thr->trace_pos) / 2) % 16;
  }
  StoreShadow(&shadow_mem[index / 4], cur.raw());
  return;
}

SHARED:
  // Need to unwind this because _mm_extract_epi8/_mm_insert_epi32 indexes must
  // be constants.
#define LOAD_EPOCH(idx)                                                        \
  if (race_mask & (1 << (idx * 4))) {                                          \
    u8 sid = _mm_extract_epi8(shadow, idx * 4 + 1);                            \
    u16 epoch = static_cast<u16>(thr->clock.Get(static_cast<Sid>(sid)));       \
    thread_epochs = _mm_insert_epi32(thread_epochs, u32(epoch) << 16, idx);    \
  }
  m128 thread_epochs = _mm_set1_epi32(0x7fffffff);
  LOAD_EPOCH(0);
  LOAD_EPOCH(1);
  LOAD_EPOCH(2);
  LOAD_EPOCH(3);
  const m128 mask_epoch = _mm_set1_epi32(0x1fff0000);
  const m128 shadow_epochs = _mm_and_si128(shadow, mask_epoch);
  const m128 concurrent = _mm_cmplt_epi32(thread_epochs, shadow_epochs);
  const int concurrent_mask = _mm_movemask_epi8(concurrent);
  DPrintf2("  MOP: shadow_epochs=%V thread_epochs=%V concurrent_mask=%04x\n",
           shadow_epochs, thread_epochs, concurrent_mask);
  if (LIKELY(concurrent_mask == 0))
    goto STORE;

  ReportRaceV(thr, shadow_mem, cur, concurrent_mask, shadow);
  return;

  /*
  bool stored = false;
  Shadow old(0);

  int idx = 0;
#include "tsan_update_shadow_word_inl.h"
  idx = 1;
#include "tsan_update_shadow_word_inl.h"
  idx = 2;
#include "tsan_update_shadow_word_inl.h"
  idx = 3;
#include "tsan_update_shadow_word_inl.h"

  // We did not find any races and had already stored
  // the current access info, so we are done.
  if (LIKELY(stored))
    return;
  {
    // Choose a random candidate slot and replace it.
    uptr index = static_cast<uptr>(cur.epoch()) % kShadowCnt; //!!! very low
entropy, epoch does not change often StoreShadow(&shadow_mem[index], cur.raw());
    StatInc(thr, StatShadowReplace);
  }
  return;
RACE:
  ReportRace(thr, shadow_mem, cur, old);
  */
}

template void MemoryAccess<false>(ThreadState*, uptr, uptr, u32, bool, bool);
template void MemoryAccess<true>(ThreadState*, uptr, uptr, u32, bool, bool);

// Called by MemoryAccessRange in tsan_rtl_thread.cpp
ALWAYS_INLINE USED void MemoryAccessImpl(ThreadState* thr, uptr addr,
                                         u32 kAccessSizeLog,
                                         bool kAccessIsWrite, bool kIsAtomic,
                                         RawShadow* shadow_mem, Shadow cur) {
  CHECK(atomic_load_relaxed(&thr->in_runtime)); //!!!
  char memBuf[4][64];
  (void)memBuf;
  DPrintf2("    Access:%p access=0x%x"
           " is_write=%d shadow=%p {%s, %s, %s, %s}\n",
           (void*)addr, (int)cur.access(), kAccessIsWrite, shadow_mem,
           DumpShadow(memBuf[0], shadow_mem[0]),
           DumpShadow(memBuf[1], shadow_mem[1]),
           DumpShadow(memBuf[2], shadow_mem[2]),
           DumpShadow(memBuf[3], shadow_mem[3]));

  if (LIKELY(ContainsSameAccess(shadow_mem, cur.raw(), !kAccessIsWrite))) {
    StatInc(thr, StatMop);
    StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
    StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));
    StatInc(thr, StatMopSame);
    return;
  }

  MemoryAccessImpl1(thr, addr, kAccessSizeLog, kAccessIsWrite, kIsAtomic,
                    shadow_mem, cur);
}

static void MemoryRangeSet(ThreadState* thr, uptr pc, uptr addr, uptr size,
                           RawShadow val) {
  CHECK(/*!thr ||*/ atomic_load_relaxed(&thr->in_runtime)); //!!!
  (void)thr;
  (void)pc;
  if (size == 0)
    return;
  // FIXME: fix me.
  /*
  uptr offset = addr % kShadowCell;
  if (offset) {
    offset = kShadowCell - offset;
    if (size <= offset)
      return;
    addr += offset;
    size -= offset;
  }
  */
  DCHECK_EQ(addr % kShadowCell, 0);
  DCHECK_EQ(size % kShadowCell, 0);
  // If a user passes some insane arguments (memset(0)),
  // let it just crash as usual.
  if (!IsAppMem(addr) || !IsAppMem(addr + size - 1))
    return;
  // Don't want to touch lots of shadow memory.
  // If a program maps 10MB stack, there is no need reset the whole range.
  // UnmapOrDie/MmapFixedNoReserve does not work on Windows.
  if (SANITIZER_WINDOWS || size < common_flags()->clear_shadow_mmap_threshold) {
    RawShadow* p = (RawShadow*)MemToShadow(addr);
    CHECK(IsShadowMem((uptr)p));
    CHECK(IsShadowMem((uptr)(p + size * kShadowCnt / kShadowCell - 1)));
    for (uptr i = 0; i < size / kShadowCell * kShadowCnt;) {
      p[i++] = val;
      for (uptr j = 1; j < kShadowCnt; j++)
        p[i++] = 0;
    }
  } else {
    // The region is big, reset only beginning and end.
    const uptr kPageSize = GetPageSizeCached();
    RawShadow* begin = (RawShadow*)MemToShadow(addr);
    RawShadow* end = begin + size / kShadowCell * kShadowCnt;
    RawShadow* p = begin;
    // Set at least first kPageSize/2 to page boundary.
    while ((p < begin + kPageSize / kShadowSize / 2) || ((uptr)p % kPageSize)) {
      *p++ = val;
      for (uptr j = 1; j < kShadowCnt; j++)
        *p++ = 0;
    }
    // Reset middle part.
    RawShadow* p1 = p;
    p = RoundDown(end, kPageSize);
    UnmapOrDie((void*)p1, (uptr)p - (uptr)p1);
    if (!MmapFixedSuperNoReserve((uptr)p1, (uptr)p - (uptr)p1))
      Die();
    // Set the ending.
    while (p < end) {
      *p++ = val;
      for (uptr j = 1; j < kShadowCnt; j++)
        *p++ = 0;
    }
  }
}

void MemoryResetRange(ThreadState* thr, uptr pc, uptr addr, uptr size) {
  ScopedRuntime sr(thr);
  addr = RoundDown(addr, kShadowCell);
  size = RoundUp(size, kShadowCell);
  MemoryRangeSet(thr, pc, addr, size, 0);
}

void MemoryRangeFreed(ThreadState* thr, uptr pc, uptr addr, uptr size) {
  DCHECK_EQ(addr % kShadowCell, 0);
  size = RoundUp(size, kShadowCell);
  // Processing more than 1k (4k of shadow) is expensive,
  // can cause excessive memory consumption (user does not necessary touch
  // the whole range) and most likely unnecessary.
  if (size > 1024)
    size = 1024;
  CHECK_EQ(thr->is_freeing, false);
  thr->is_freeing = true;
  MemoryAccessRange(thr, pc, addr, size, true);
  thr->is_freeing = false;
  {
    ScopedRuntime rt(thr);
    TraceMemoryAccessRange(thr, pc, addr, size, false, true);
    Shadow s(thr->fast_state);
    s.SetAccess(0, kSizeLog8, false, false, true);
    MemoryRangeSet(thr, pc, addr, size, s.raw());
  }
}

void MemoryRangeImitateWrite(ThreadState* thr, uptr pc, uptr addr, uptr size) {
  ScopedRuntime rt(thr);
  DCHECK_EQ(addr % kShadowCell, 0);
  size = RoundUp(size, kShadowCell);
  TraceMemoryAccessRange(thr, pc, addr, size, false, false);
  Shadow s(thr->fast_state);
  s.SetAccess(0, kSizeLog8, false, false, false);
  MemoryRangeSet(thr, pc, addr, size, s.raw());
}

void MemoryRangeImitateWriteOrReset(ThreadState* thr, uptr pc, uptr addr,
                                    uptr size) {
  if (thr->ignore_reads_and_writes == 0)
    MemoryRangeImitateWrite(thr, pc, addr, size);
  else
    MemoryResetRange(thr, pc, addr, size);
}

void MBlockAlloc(ThreadState* thr, uptr pc, uptr p, uptr sz) {
  ScopedRuntime sr(thr);
  ctx->metamap.AllocBlock(thr, pc, p, sz);
}

uptr MBlockFree(ThreadState* thr, uptr pc, uptr p) {
  ScopedRuntime sr(thr);
  return ctx->metamap.FreeBlock(thr->proc(), p);
}

ALWAYS_INLINE WARN_UNUSED_RESULT bool TraceFunc(ThreadState* thr,
                                                EventType type, uptr pc = 0) {
  DCHECK(type == EventTypeFuncEnter || type == EventTypeFuncExit);
  if (!kCollectHistory)
    return true;
  EventPC* ev;
  if (!TraceAcquire(thr, &ev))
    return false;
  ev->isAccess = 0;
  ev->type = type;
  ev->isExternalPC = 0;
  ev->_ = 0;
  ev->pc = pc;
  TraceRelease(thr, ev);
  return true;
}

void TraceMemoryAccessRange(ThreadState* thr, uptr pc, uptr addr, uptr size,
                            bool isRead, bool isFreed) {
  if (!kCollectHistory)
    return;
  thr->trace_prev_pc = pc;
  EventAccessEx ev = {};
  ev.type = EventTypeAccessEx;
  ev.isRead = isRead;
  ev.isAtomic = 0;
  ev.isFreed = isFreed;
  ev.isExternalPC = 0; //!!!
  ev.sizeLo = size;
  ev.pc = pc;
  ev.isNotAccess = 0;
  ev.addr = addr;
  ev.sizeHi = size >> 13;
  //!!! CHECK_EQ(ev->sizeLo + (ev->sizeHi << 13), size);
  TraceEvent(thr, ev);
}

void TraceMutexLock(ThreadState* thr, EventType type, uptr pc, uptr addr,
                    StackID stk) {
  DCHECK(type == EventTypeLock || type == EventTypeRLock);
  if (!kCollectHistory)
    return;
  //!!! should these events set trace_prev_pc as well?
  EventLock ev = {};
  ev.type = type;
  ev.isExternalPC = 0; //!!! handle
  ev.pc = pc;
  ev.stackIDLo = static_cast<u64>(stk);
  ev.stackIDHi = static_cast<u64>(stk) >> 16;
  ev.addr = addr;
  TraceEvent(thr, ev);
}

void TraceMutexUnlock(ThreadState* thr, uptr addr) {
  if (!kCollectHistory)
    return;
  EventUnlock ev = {};
  ev.type = EventTypeUnlock;
  ev.addr = addr;
  TraceEvent(thr, ev);
}

void TraceRelease(ThreadState* thr) {
  if (!kCollectHistory)
    return;
  EventPC ev = {};
  ev.type = EventTypeRelease;
  TraceEvent(thr, ev);
}

void TraceSlotAttach(ThreadState* thr) {
  if (!kCollectHistory)
    return;
  EventAttach ev = {};
  ev.type = EventTypeAttach;
  ev.tid = static_cast<u64>(thr->tid);
  TraceEvent(thr, ev);
}

template <bool kInRuntime>
NOINLINE void TraceRestartFuncEntry(ThreadState* thr, uptr pc) {
  MaybeScopedRuntime<kInRuntime> rt(thr);
  TraceSwitch(thr);
  FuncEntry(thr, pc);
}

template <bool kInRuntime>
ALWAYS_INLINE USED void FuncEntry(ThreadState* thr, uptr pc) {
  DCHECK_EQ(kInRuntime, atomic_load_relaxed(&thr->in_runtime));
  StatInc(thr, StatFuncEnter);
  DPrintf2("#%d: FuncEntry %p\n", (int)thr->fast_state.sid(), (void*)pc);
  if (thr->ignore_funcs_) //!!! combine with TracePos check?
    return;
  if (!TraceFunc(thr, EventTypeFuncEnter, pc))
    return TraceRestartFuncEntry<kInRuntime>(thr, pc);
  DCHECK_GE(thr->shadow_stack_pos, thr->shadow_stack);
#if !SANITIZER_GO
  DCHECK_LT(thr->shadow_stack_pos, thr->shadow_stack_end);
#else
  if (thr->shadow_stack_pos == thr->shadow_stack_end)
    GrowShadowStack(thr);
#endif
  thr->shadow_stack_pos[0] = pc;
  thr->shadow_stack_pos++;
}

template void FuncEntry<false>(ThreadState*, uptr pc);
template void FuncEntry<true>(ThreadState*, uptr pc);

template <bool kInRuntime>
NOINLINE void TraceRestartFuncExit(ThreadState* thr) {
  MaybeScopedRuntime<kInRuntime> rt(thr);
  TraceSwitch(thr);
  FuncExit(thr);
}

template <bool kInRuntime> ALWAYS_INLINE USED void FuncExit(ThreadState* thr) {
  DCHECK_EQ(kInRuntime, atomic_load_relaxed(&thr->in_runtime));
  StatInc(thr, StatFuncExit);
  DPrintf2("#%d: FuncExit\n", (int)thr->fast_state.sid());
  if (thr->ignore_funcs_) //!!! combine with TracePos check?
    return;
  if (!TraceFunc(thr, EventTypeFuncExit, 0))
    return TraceRestartFuncExit<kInRuntime>(thr);
  DCHECK_GT(thr->shadow_stack_pos, thr->shadow_stack);
#if !SANITIZER_GO
  DCHECK_LT(thr->shadow_stack_pos, thr->shadow_stack_end);
#endif
  thr->shadow_stack_pos--;
}

template void FuncExit<false>(ThreadState*);
template void FuncExit<true>(ThreadState*);

void ThreadIgnoreBegin(ThreadState* thr, uptr pc, bool save_stack) {
  DPrintf("#%d: ThreadIgnoreBegin\n", thr->tid);
  thr->ignore_reads_and_writes++;
  CHECK_GT(thr->ignore_reads_and_writes, 0);
  thr->ignore_enabled_ = true;
#if !SANITIZER_GO
  if (save_stack && !ctx->after_multithreaded_fork)
    thr->mop_ignore_set.Add(CurrentStackId(thr, pc));
#endif
}

void ThreadIgnoreEnd(ThreadState* thr, uptr pc) {
  DPrintf("#%d: ThreadIgnoreEnd\n", thr->tid);
  CHECK_GT(thr->ignore_reads_and_writes, 0);
  thr->ignore_reads_and_writes--;
  if (thr->ignore_reads_and_writes == 0) {
    thr->ignore_enabled_ = false;
#if !SANITIZER_GO
    thr->mop_ignore_set.Reset();
#endif
  }
}

#if !SANITIZER_GO
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
__tsan_testonly_shadow_stack_current_size() {
  ThreadState* thr = cur_thread();
  return thr->shadow_stack_pos - thr->shadow_stack;
}
#endif

void ThreadIgnoreSyncBegin(ThreadState* thr, uptr pc, bool save_stack) {
  DPrintf("#%d: ThreadIgnoreSyncBegin\n", thr->tid);
  thr->ignore_sync++;
  CHECK_GT(thr->ignore_sync, 0);
#if !SANITIZER_GO
  if (save_stack && !ctx->after_multithreaded_fork)
    thr->sync_ignore_set.Add(CurrentStackId(thr, pc));
#endif
}

void ThreadIgnoreSyncEnd(ThreadState* thr, uptr pc) {
  DPrintf("#%d: ThreadIgnoreSyncEnd\n", thr->tid);
  CHECK_GT(thr->ignore_sync, 0);
  thr->ignore_sync--;
#if !SANITIZER_GO
  if (thr->ignore_sync == 0)
    thr->sync_ignore_set.Reset();
#endif
}

#if SANITIZER_DEBUG
void build_consistency_debug() {
}
#else
void build_consistency_release() {
}
#endif

#if TSAN_COLLECT_STATS
void build_consistency_stats() {
}
#else
void build_consistency_nostats() {
}
#endif

} // namespace __tsan

extern "C" uptr __tsan_compress(uptr addr) {
  return __tsan::MemToShadow(addr);
}

#if !SANITIZER_GO
// Must be included in this file to make sure everything is inlined.
#include "tsan_interface_inl.h"
#endif
