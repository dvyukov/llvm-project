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
#include <dlfcn.h>
SANITIZER_WEAK_CXX_DEFAULT_IMPL
bool OnFinalize(bool failed) {
#if !SANITIZER_GO
  if (auto* ptr = dlsym(RTLD_DEFAULT, "__tsan_on_finalize"))
    return reinterpret_cast<decltype(&__tsan_on_finalize)>(ptr)(failed);
#endif
  return failed;
}
SANITIZER_WEAK_CXX_DEFAULT_IMPL
void OnInitialize() {
#if !SANITIZER_GO
  if (auto* ptr = dlsym(RTLD_DEFAULT, "__tsan_on_initialize")) {
    return reinterpret_cast<decltype(&__tsan_on_initialize)>(ptr)();
  }
#endif
}
#endif

static TracePart* TracePartAlloc() {
  TracePart* part;
  {
    Lock l(&ctx->trace_part_mtx);
    part = ctx->trace_part_cache;
    if (part)
      ctx->trace_part_cache = part->next;
    if (++ctx->trace_part_count > kMaxSid * 512) //!!! when do we reset for real?
      atomic_store_relaxed(&ctx->reset_scheduled, 1);
  }
  if (!part)
    part = (TracePart*)MmapOrDie(sizeof(TracePart), "TracePart");
  part->next = nullptr;
  internal_memset(part->events, 0, sizeof(part->events)); //!!! is this needed
  return part;
}

static void TracePartFree(TracePart* part) {
  // Note: this runs only during reset when no other threads are running.
  //UnmapOrDie(part, sizeof(*part));
  part->next = ctx->trace_part_cache;
  ctx->trace_part_cache = part;
  CHECK_GT(ctx->trace_part_count, 0);
  ctx->trace_part_count--;
}

void DoReset() {
  DPrintf("Resetting threads...\n");
  CHECK(!atomic_load_relaxed(&ctx->reset_pending));
  //!!! part new threads
  //!!! degerister dead threads
  //!!! this should reset slots
  for (u32 i = ctx->thread_registry.NumThreadsLocked(); i--;) {
    ThreadContext* tctx = (ThreadContext*)ctx->thread_registry.GetThreadLocked(static_cast<Tid>(i));
    if (!tctx || tctx->status != ThreadStatusRunning)
      continue;
    //!!! do this when the thread first attaches after reset
    ThreadState* thr = tctx->thr;
    thr->clock.Reset();
#if !SANITIZER_GO
    thr->last_sleep_stack_id = kInvalidStackID;
    thr->last_sleep_clock.Reset();
#endif
    //!!! thr->fast_state.SetEpoch(1);
    //!!! thr->clock.Set(thr->tid, 1);
  }
  for (auto& slot: ctx->slots) {
    CHECK(!slot.thr);
    CHECK(!slot.reset_wait);
    slot.dirty = false;
    slot.clock.Reset();
    for (TracePart* part = slot.trace.first; part;) {
      TracePart* next = part->next;
      TracePartFree(part);
      part = next;
    }
    slot.trace.first = slot.trace.current = nullptr;
    slot.trace.pos = 0;
    slot.trace.prev_pc = 0;
  }
  DPrintf("Resetting shadow...\n");
  if (!MmapFixedNoReserve(ShadowBeg(), ShadowEnd() - ShadowBeg(), "shadow")) {
    Printf("failed to reset shadow memory\n");
    Die();
  }
  DPrintf("Resetting meta shadow...\n");
  ctx->metamap.Reset();
  //!!! purge all dead threads from thread_registry
  /*
  DPrintf("Resuming threads...\n");
  for (u32 i = ctx->thread_registry.NumThreadsLocked(); i--;) {
    ThreadContext* tctx = (ThreadContext*)ctx->thread_registry.GetThreadLocked(static_cast<Tid>(i));
    if (!tctx || !tctx->reset_wait)
      continue;
    CHECK_EQ(tctx->status, ThreadStatusRunning);
    tctx->reset_wait = false;
    tctx->reset_sema.Post();
  }
  */
}

void CompleteReset(ThreadState *thr) {
  SlotDetach(thr);
  SlotAttach(thr);
}

TidSlot& FindAttachSlot(ThreadState* thr) {
  CHECK(!thr->slot);
  for (;;) {
    if (!atomic_load_relaxed(&ctx->reset_pending)) {
      if (thr->last_slot && !thr->last_slot->thr && thr->last_slot->clock.Get(thr->last_slot->sid) != kLastEpoch)
        return *thr->last_slot;
      for (auto& slot : ctx->slots) {
        if (slot.dirty || slot.clock.Get(slot.sid) == kLastEpoch)
          continue;
        if (!slot.thr)
          return slot;
      }
      for (auto& slot : ctx->slots) {
        if (slot.clock.Get(slot.sid) == kLastEpoch)
          continue;
        if (!slot.thr)
          return slot;
      }
      DPrintf("#%d: InitiateReset\n", thr->tid);
      int pending = 0;
      for (auto& slot : ctx->slots) {
        if (!slot.thr)
          continue;
        DPrintf("#%d: InitiateReset waiting for %d\n", thr->tid, slot.sid);
        CHECK(!slot.reset_wait);
        slot.reset_wait = true;
        pending++;
      }
      if (!pending) {
        DoReset();
        continue;
      }
      atomic_store_relaxed(&ctx->reset_pending, pending);
    }
    ctx->thread_registry.Unlock();
    internal_usleep(100);
    ctx->thread_registry.Lock();
  }
}

void SlotAttach(ThreadState *thr) {
  ThreadRegistryLock lock(&ctx->thread_registry);
  TidSlot& slot = FindAttachSlot(thr);
  DPrintf("#%d: SlotAttach: slot=%u\n", thr->tid, slot.sid);
  CHECK(!slot.thr);
  CHECK(!thr->slot);
  slot.thr = thr;
  thr->slot = &slot;
  thr->last_slot = &slot;
  slot.dirty = true;
  //!!! skip acquire and increment if we we are attaching to the same slot
  u16 epoch = static_cast<u16>(slot.clock.Get(slot.sid)) + 1;
  CHECK(epoch);
  slot.clock.Set(slot.sid, static_cast<Epoch>(epoch));  
  thr->clock.Acquire(&slot.clock);
  thr->fast_state.SetSid(slot.sid);
  thr->fast_state.SetEpoch(thr->clock.Get(slot.sid));
  if (!slot.trace.first) {
    CHECK_EQ(slot.trace.pos, 0);
    slot.trace.first = slot.trace.current = TracePartAlloc();
  }
  //!!! check that we have enough trace space for the next event below
  thr->trace_pos = &slot.trace.current->events[slot.trace.pos];
  thr->trace_prev_pc = slot.trace.prev_pc;
  // While we cache trace data in thr, the data in the trace itself
  // is not up-to-date and should not be used.
  slot.trace.pos = -1;
  slot.trace.prev_pc = -1;
  //!!! do this only on the first attach
  thr->tctx->startMutexSet = thr->mset;
  thr->tctx->startStack.Init(thr->shadow_stack, thr->shadow_stack_pos - thr->shadow_stack);
  TraceSlotAttach(thr);
}

void SlotDetach(ThreadState *thr) {
  ThreadRegistryLock lock(&ctx->thread_registry);
  CHECK(thr->slot);
  CHECK_EQ(thr->slot->thr, thr);
  TidSlot& slot = *thr->slot;
  DPrintf("#%d: SlotDetach: slot=%u\n", thr->tid, slot.sid);
  thr->slot = nullptr;
  slot.thr = nullptr;
  CHECK(!slot.reset_wait || atomic_load_relaxed(&ctx->reset_pending));
  slot.trace.pos = thr->trace_pos - &slot.trace.current->events[0];
  CHECK_LE(slot.trace.pos, ARRAY_SIZE(slot.trace.current->events));
  slot.trace.prev_pc = thr->trace_prev_pc;
  thr->trace_pos = nullptr;
  thr->trace_prev_pc = -1;
  slot.clock = thr->clock;
  if (slot.reset_wait) {
    slot.reset_wait = false;
    int pending = atomic_load_relaxed(&ctx->reset_pending) - 1;
    DPrintf("#%d: CompleteReset: pending=%d\n", thr->tid, pending);
    CHECK_GE(pending, 0);
    atomic_store_relaxed(&ctx->reset_pending, pending);
    if (!pending)
      DoReset();
  } else if (atomic_load_relaxed(&ctx->reset_scheduled)) {
    atomic_store_relaxed(&ctx->reset_scheduled, 0);
    DPrintf("#%d: InitiateReset\n", thr->tid);
    int pending = 0;
    for (auto& slot : ctx->slots) {
      if (!slot.thr)
        continue;
      DPrintf("#%d: InitiateReset waiting for %d\n", thr->tid, slot.sid);
      CHECK(!slot.reset_wait);
      slot.reset_wait = true;
      pending++;
    }
    if (!pending)
      DoReset();
    else
      atomic_store_relaxed(&ctx->reset_pending, pending);
  }
}

Context::Context()
    : initialized(), report_mtx(MutexTypeReport, StatMtxReport), nreported(),
      nmissed_expected(),
      thread_registry([](Tid tid) -> ThreadContextBase* {
          return new(Alloc(sizeof(ThreadContext))) ThreadContext(tid);
      }),
      racy_mtx(MutexTypeRacy, StatMtxRacy), racy_stacks(), racy_addresses(),
      fired_suppressions_mtx(MutexTypeFired, StatMtxFired),
      trace_part_mtx(MutexTypeTraceAlloc, StatMtxTraceAlloc) {
  fired_suppressions.reserve(8);
  for (uptr i = 0; i < kMaxSid; i++)
    slots[i].sid = static_cast<Sid>(i);
}

// The objects are allocated in TLS, so one may rely on zero-initialization.
ThreadState::ThreadState(Tid tid)
// Do not touch these, rely on zero initialization,
// they may be accessed before the ctor.
// ignore_reads_and_writes()
// ignore_interceptors()
    : tid(tid) {
  //clock.Set(tid, epoch);
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
#if 0
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
        SymbolizeFlush();
        atomic_store(&ctx->last_symbolize_time_ns, 0, memory_order_relaxed);
      }
    }
  }
  return nullptr;
}
#endif

static void StartBackgroundThread() {
  //!!! do we still need the background thread?
  //ctx->background_thread = internal_start_thread(&BackgroundThread, 0);
}

#ifndef __mips__
static void StopBackgroundThread() {
  //atomic_store(&ctx->stop_background_thread, 1, memory_order_relaxed);
  //internal_join_thread(ctx->background_thread);
  //ctx->background_thread = 0;
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
  HandleDeadlySignal(siginfo, context, static_cast<Tid>(GetTid()), &OnStackUnwind, nullptr);
}
#endif

void Initialize(ThreadState* thr) {
  // Thread safe because done before all threads exist.
  static bool is_initialized = false;
  if (is_initialized)
    return;
  is_initialized = true;
  // We are not ready to handle interceptors yet.
  ScopedIgnoreInterceptors ignore;
  SanitizerToolName = "ThreadSanitizer";
  // Install tool-specific callbacks in sanitizer_common.
  SetCheckFailedCallback(CheckFailed);

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
  Symbolizer::GetOrInit()->AddHooks(EnterSymbolizer, ExitSymbolizer);
#endif

  VPrintf(1, "***** Running under ThreadSanitizer v3 (pid %d) *****\n",
          (int)internal_getpid());

  // Initialize thread 0.
  Tid tid = ThreadCreate(thr, 0, 0, true);
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
  ro.SetWrite(false);
  CHECK_EQ(ro.raw(), kShadowRodata);

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
    internal_usleep(u64(flags()->atexit_sleep_ms)*1000);

  // Wait for pending reports.
  ctx->report_mtx.Lock();
  { ScopedErrorReportLock l; }
  ctx->report_mtx.Unlock();

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
#if !SANITIZER_GO
  if (flags()->print_benign)
    PrintMatchedBenignRaces();
#endif

  failed = OnFinalize(failed);

#if TSAN_COLLECT_STATS
  StatAggregate(ctx->stat, thr->stat);
  StatOutput(ctx->stat);
#endif

  return failed ? common_flags()->exitcode : 0;
}

#if !SANITIZER_GO
void ForkBefore(ThreadState* thr, uptr pc) {
  ctx->thread_registry.Lock();
  ctx->report_mtx.Lock();
  // Ignore memory accesses in the pthread_atfork callbacks.
  // If any of them triggers a data race we will deadlock
  // on the report_mtx.
  // We could ignore interceptors and sync operations as well,
  // but so far it's unclear if it will do more good or harm.
  // Unnecessarily ignoring things can lead to false positives later.
  ThreadIgnoreBegin(thr, pc);
}

void ForkParentAfter(ThreadState* thr, uptr pc) {
  ThreadIgnoreEnd(thr, pc); // Begin is in ForkBefore.
  ctx->report_mtx.Unlock();
  ctx->thread_registry.Unlock();
}

void ForkChildAfter(ThreadState* thr, uptr pc) {
  ThreadIgnoreEnd(thr, pc); // Begin is in ForkBefore.
  ctx->report_mtx.Unlock();
  ctx->thread_registry.Unlock();

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
  auto part = thr->slot->trace.current;
  if (thr->trace_pos + 1 < &part->events[ARRAY_SIZE(part->events)])
    return;
#if !SANITIZER_GO
  if (ctx->after_multithreaded_fork)
    return;
#endif
  // Comment for this:
  // tsan: do not call malloc/free in memory access handling routine.
  // This improves signal-/fork-safety of instrumented programs.
  // Date:   Fri Jun 22 11:08:55 2012 +0000
  //!!! thr->nomalloc++;
  part = TracePartAlloc();
  thr->slot->trace.current->next = part;
  thr->slot->trace.current = part;
  thr->slot->trace.pos = 0;
  thr->trace_pos = &part->events[0];
  //thr->nomalloc--;
}

#if !SANITIZER_GO
extern "C" void __tsan_trace_switch() {
  TraceSwitch(cur_thread());
}
#endif

ALWAYS_INLINE Shadow LoadShadow(RawShadow* p) {
  return Shadow(atomic_load((atomic_uint32_t*)p, memory_order_relaxed));
}

ALWAYS_INLINE void StoreShadow(RawShadow* sp, RawShadow s) {
  atomic_store((atomic_uint32_t*)sp, s, memory_order_relaxed);
}

ALWAYS_INLINE
void StoreAndZero(RawShadow* sp, RawShadow* s) {
  StoreShadow(sp, *s);
  *s = 0;
}

static inline bool HappensBefore(Shadow old, ThreadState* thr) {
  return thr->clock.Get(old.sid()) >= old.epoch();
}

ALWAYS_INLINE
void MemoryAccessImpl1(ThreadState* thr, uptr addr, int kAccessSizeLog,
                       bool kAccessIsWrite, bool kIsAtomic, RawShadow* shadow_mem,
                       Shadow cur) {
  StatInc(thr, StatMop);
  StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
  StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));

  RawShadow store_word = cur.raw();

  // scan all the shadow values and dispatch to 4 categories:
  // same, replace, candidate and race (see comments below).
  // we consider only 3 cases regarding access sizes:
  // equal, intersect and not intersect. initially I considered
  // larger and smaller as well, it allowed to replace some
  // 'candidates' with 'same' or 'replace', but I think
  // it's just not worth it (performance- and complexity-wise).

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
  if (LIKELY(store_word == 0))
    return;
  {
    // Choose a random candidate slot and replace it.
    uptr index = static_cast<uptr>(cur.epoch()) % kShadowCnt; //!!! very low entropy, epoch does not change often
    StoreShadow(&shadow_mem[index], store_word);
    StatInc(thr, StatShadowReplace);
  }
  return;
RACE:
  thr->racy_state[0] = cur;
  thr->racy_state[1] = old;
  thr->racy_shadow_addr = shadow_mem;
  ReportRace(thr);
}

void UnalignedMemoryAccess(ThreadState* thr, uptr pc, uptr addr, int size,
                           bool kAccessIsWrite, bool kIsAtomic) {
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
    if (isRead && old.raw() == kShadowRodata)
      return true;
    //!!! speed up, this is used at least for Go.
    if (Shadow::Addr0AndSizeAreEqual(cur, old) &&
        old.sid() == cur.sid() &&
        old.epoch() == cur.epoch() &&
        !old.IsFreed() &&
        old.IsAtomic() == cur.IsAtomic() &&
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
    const m128 read_mask = _mm_set1_epi32(kShadowRodata);
    //!!! we can also skip it for range memory access, they already checked rodata.
#if !SANITIZER_GO
    const m128 ro = _mm_cmpeq_epi32(shadow, read_mask);
#endif
    const m128 masked_shadow = _mm_or_si128(shadow, read_mask);
    const m128 same = _mm_cmpeq_epi32(masked_shadow, access);
#if !SANITIZER_GO
    const m128 res = _mm_or_si128(ro, same);
    return _mm_movemask_epi8(res);
#else
    return _mm_movemask_epi8(same);
#endif
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
  internal_snprintf(buf, 64, "{tid=%u@%u addr=%u/%u type=%u/%u/%u}",
      static_cast<u32>(s.sid()), static_cast<u32>(s.epoch()),
      s.addr0(), s.size(), s.IsRead(), s.IsAtomic(), s.IsFreed());
  return buf;
}

ALWAYS_INLINE USED void MemoryAccess(ThreadState* thr, uptr pc, uptr addr,
                                     int kAccessSizeLog, bool kAccessIsWrite, //!!! change all kAccessIsWrite to isRead
                                     bool kIsAtomic) {
  RawShadow* shadow_mem = (RawShadow*)MemToShadow(addr);
  char memBuf[4][64];
  (void)memBuf;
  DPrintf2("#%d: Access: @%p %p size=%d"
           " is_write=%d shadow=%p {%s, %s, %s, %s}\n",
           (int)thr->tid, (void*)pc, (void*)addr,
           (int)(1 << kAccessSizeLog), kAccessIsWrite, shadow_mem,
           DumpShadow(memBuf[0], shadow_mem[0]), DumpShadow(memBuf[1], shadow_mem[1]),
           DumpShadow(memBuf[2], shadow_mem[2]), DumpShadow(memBuf[3], shadow_mem[3]));
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

/*
  if (!SANITIZER_GO && !kAccessIsWrite && *shadow_mem == kShadowRodata) {
    // Access to .rodata section, no races here.
    // Measurements show that it can be 10-20% of all memory accesses.
    StatInc(thr, StatMop);
    StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
    StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));
    StatInc(thr, StatMopRodata);
    return;
  }
*/

  Shadow cur(thr->fast_state);
  cur.SetAccess(addr, kAccessSizeLog, !kAccessIsWrite, kIsAtomic);
  //cur.SetAddr0AndSizeLog(addr & 7, kAccessSizeLog);
  //cur.SetWrite(kAccessIsWrite);
  //cur.SetAtomic(kIsAtomic);

  if (LIKELY(ContainsSameAccess(shadow_mem, cur.raw(), !kAccessIsWrite))) {
    StatInc(thr, StatMop);
    StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
    StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));
    StatInc(thr, StatMopSame);
    return;
  }

  if (UNLIKELY(thr->ignore_enabled_)) {
    StatInc(thr, StatMop);
    StatInc(thr, kAccessIsWrite ? StatMopWrite : StatMopRead);
    StatInc(thr, (StatType)(StatMop1 + kAccessSizeLog));
    StatInc(thr, StatMopIgnored);
    return;
  }

  TraceAddMemoryAccess(thr, pc, addr, kAccessSizeLog, !kAccessIsWrite, kIsAtomic);
  MemoryAccessImpl1(thr, addr, kAccessSizeLog, kAccessIsWrite, kIsAtomic,
                    shadow_mem, cur);
}

// Called by MemoryAccessRange in tsan_rtl_thread.cpp
ALWAYS_INLINE USED void MemoryAccessImpl(ThreadState* thr, uptr addr,
                                         int kAccessSizeLog,
                                         bool kAccessIsWrite, bool kIsAtomic,
                                         RawShadow* shadow_mem, Shadow cur) {
  char memBuf[4][64];
  (void)memBuf;
  DPrintf2("    Access:%p size=%d"
           " is_write=%d shadow=%p {%s, %s, %s, %s}\n",
           (void*)addr,
           (int)(1 << kAccessSizeLog), kAccessIsWrite, shadow_mem,
           DumpShadow(memBuf[0], shadow_mem[0]), DumpShadow(memBuf[1], shadow_mem[1]),
           DumpShadow(memBuf[2], shadow_mem[2]), DumpShadow(memBuf[3], shadow_mem[3]));

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
  TraceAddMemoryAccessRange(thr, pc, addr, size, false, true);
  Shadow s(thr->fast_state);
  s.MarkAsFreed();
  s.SetWrite(true);
  s.SetAddr0AndSizeLog(0, kSizeLog8);
  MemoryRangeSet(thr, pc, addr, size, s.raw());
}

void MemoryRangeImitateWrite(ThreadState* thr, uptr pc, uptr addr, uptr size) {
  DCHECK_EQ(addr % kShadowCell, 0);
  size = RoundUp(size, kShadowCell);
  TraceAddMemoryAccessRange(thr, pc, addr, size, false, false);
  Shadow s(thr->fast_state);
  s.SetWrite(true);
  s.SetAddr0AndSizeLog(0, kSizeLog8);
  MemoryRangeSet(thr, pc, addr, size, s.raw());
}

void MemoryRangeImitateWriteOrResetRange(ThreadState* thr, uptr pc, uptr addr,
                                         uptr size) {
  if (thr->ignore_reads_and_writes == 0)
    MemoryRangeImitateWrite(thr, pc, addr, size);
  else
    MemoryResetRange(thr, pc, addr, size);
}

ALWAYS_INLINE USED void FuncEntry(ThreadState* thr, uptr pc) {
  StatInc(thr, StatFuncEnter);
  DPrintf2("#%d: FuncEntry %p\n", (int)thr->fast_state.sid(), (void*)pc);
  TraceEvent(thr, EventTypeFuncEnter, pc);

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

ALWAYS_INLINE USED void FuncExit(ThreadState* thr) {
  StatInc(thr, StatFuncExit);
  DPrintf2("#%d: FuncExit\n", (int)thr->fast_state.sid());
  TraceEvent(thr, EventTypeFuncExit);

  DCHECK_GT(thr->shadow_stack_pos, thr->shadow_stack);
#if !SANITIZER_GO
  DCHECK_LT(thr->shadow_stack_pos, thr->shadow_stack_end);
#endif
  thr->shadow_stack_pos--;
}

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
