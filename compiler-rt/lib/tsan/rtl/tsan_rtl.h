//===-- tsan_rtl.h ----------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// Main internal TSan header file.
//
// Ground rules:
//   - C++ run-time should not be used (static CTORs, RTTI, exceptions, static
//     function-scope locals)
//   - All functions/classes/etc reside in namespace __tsan, except for those
//     declared in tsan_interface.h.
//   - Platform-specific files should be used instead of ifdefs (*).
//   - No system headers included in header files (*).
//   - Platform specific headres included only into platform-specific files (*).
//
//  (*) Except when inlining is critical for performance.
//===----------------------------------------------------------------------===//

#ifndef TSAN_RTL_H
#define TSAN_RTL_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_asm.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_deadlock_detector_interface.h"
#include "sanitizer_common/sanitizer_libignore.h"
#include "sanitizer_common/sanitizer_suppressions.h"
#include "sanitizer_common/sanitizer_thread_registry.h"
#include "sanitizer_common/sanitizer_vector.h"
#include "tsan_clock.h"
#include "tsan_defs.h"
#include "tsan_flags.h"
#include "tsan_mman.h"
#include "tsan_sync.h"
#include "tsan_trace.h"
#include "tsan_report.h"
#include "tsan_platform.h"
#include "tsan_mutexset.h"
#include "tsan_ignoreset.h"
#include "tsan_stack_trace.h"
#include "tsan_shadow.h"

#if SANITIZER_WORDSIZE != 64
# error "ThreadSanitizer is supported only on 64-bit platforms"
#endif

namespace __tsan {

#if !SANITIZER_GO
struct MapUnmapCallback;
#if defined(__mips64) || defined(__aarch64__) || defined(__powerpc__)

struct AP32 {
  static const uptr kSpaceBeg = 0;
  static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
  static const uptr kMetadataSize = 0;
  typedef __sanitizer::CompactSizeClassMap SizeClassMap;
  static const uptr kRegionSizeLog = 20;
  using AddressSpaceView = LocalAddressSpaceView;
  typedef __tsan::MapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
};
typedef SizeClassAllocator32<AP32> PrimaryAllocator;
#else
struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const uptr kSpaceBeg = Mapping::kHeapMemBeg;
  static const uptr kSpaceSize = Mapping::kHeapMemEnd - Mapping::kHeapMemBeg;
  static const uptr kMetadataSize = 0;
  typedef DefaultSizeClassMap SizeClassMap;
  typedef __tsan::MapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};
typedef SizeClassAllocator64<AP64> PrimaryAllocator;
#endif
typedef CombinedAllocator<PrimaryAllocator> Allocator;
typedef Allocator::AllocatorCache AllocatorCache;
Allocator *allocator();
#endif

struct ThreadSignalContext;

struct JmpBuf {
  uptr sp;
  int int_signal_send;
  bool in_blocking_func;
  uptr in_signal_handler;
  uptr *shadow_stack_pos;
};

// A Processor represents a physical thread, or a P for Go.
// It is used to store internal resources like allocate cache, and does not
// participate in race-detection logic (invisible to end user).
// In C++ it is tied to an OS thread just like ThreadState, however ideally
// it should be tied to a CPU (this way we will have fewer allocator caches).
// In Go it is tied to a P, so there are significantly fewer Processor's than
// ThreadState's (which are tied to Gs).
// A ThreadState must be wired with a Processor to handle events.
struct Processor { //!!! move Processor to TidSlot
  ThreadState *thr; // currently wired thread, or nullptr
#if !SANITIZER_GO
  AllocatorCache alloc_cache;
  InternalAllocatorCache internal_alloc_cache;
#endif
  DenseSlabAllocCache block_cache;
  DenseSlabAllocCache sync_cache;
  DDPhysicalThread *dd_pt;
};

#if !SANITIZER_GO
// ScopedGlobalProcessor temporary setups a global processor for the current
// thread, if it does not have one. Intended for interceptors that can run
// at the very thread end, when we already destroyed the thread processor.
struct ScopedGlobalProcessor {
  ScopedGlobalProcessor();
  ~ScopedGlobalProcessor();
};
#endif

struct TidSlot { //!!! pad/align to cache line
  Sid sid;
  ThreadState* thr;
  TidSlot* next;
  TidSlot* prev;
  bool reset_wait;
  Trace trace;
  //bool dirty;
  VectorClock clock;
};

// This struct is stored in TLS.
struct ThreadState {
  Shadow fast_state;
  bool ignore_enabled_;
  int ignore_funcs_;

  uptr *shadow_stack_pos;
  uptr *shadow_stack_end;

  atomic_uintptr_t trace_pos; // Event*
  uptr trace_prev_pc;

  atomic_sint32_t in_runtime;
  atomic_sint32_t reset_pending;

  // Technically `current` should be a separate THREADLOCAL variable;
  // but it is placed here in order to share cache line with previous fields.
  ThreadState* current;

  VectorClock clock;

  // This is a slow path flag. On fast paths, ignore_enabled_ is used.
  // We do not distinguish beteween ignoring reads and writes for better performance.
  int ignore_reads_and_writes;
  int ignore_sync;
  int suppress_reports;
  // Go does not support ignores.
#if SANITIZER_GO
  // Go uses malloc-allocated shadow stack with dynamic size.
  uptr *shadow_stack;
#else
  // C/C++ uses fixed size shadow stack embed into Trace.
  //!!! this does not hold anymore
  // Must be last to catch overflow as paging fault.
  // Go shadow stack is dynamically allocated.
  uptr shadow_stack[kShadowStackSize];
#endif

#if !SANITIZER_GO
  IgnoreSet mop_ignore_set;
  IgnoreSet sync_ignore_set;
#endif
  MutexSet mset;
  bool need_epoch_increment;
#if !SANITIZER_GO
  Vector<JmpBuf> jmp_bufs;
  int ignore_interceptors;
  int range_access_race;
  bool range_race;
  int in_symbolizer;
  bool in_ignored_lib;
  bool is_inited;
  bool is_dead;
  bool unwind_abort;
#endif
#if TSAN_COLLECT_STATS
  u64 stat[StatCnt];
#endif
  const Tid tid;
  bool active;
  bool is_freeing;
  bool is_vptr_access;
  uptr stk_addr;
  uptr stk_size;
  uptr tls_addr;
  uptr tls_size;
  ThreadContext *tctx;

#if SANITIZER_DEBUG && !SANITIZER_GO
  InternalDeadlockDetector internal_deadlock_detector;
#endif
  DDLogicalThread *dd_lt;

  TidSlot *slot;
  TidSlot *last_slot;

  // Current wired Processor, or nullptr. Required to handle any events.
  Processor *proc1;
#if !SANITIZER_GO
  Processor *proc() { return proc1; }
#else
  Processor *proc();
#endif

  atomic_uintptr_t in_signal_handler;
  ThreadSignalContext *signal_ctx;

#if !SANITIZER_GO
  StackID last_sleep_stack_id;
  VectorClock last_sleep_clock;
#endif

  // Set in regions of runtime that must be signal-safe and fork-safe.
  // If set, malloc must not be called.
  int nomalloc;

  const ReportDesc *current_report;

  explicit ThreadState(Tid tid);
} ALIGNED(64);

#if !SANITIZER_GO
#if SANITIZER_MAC || SANITIZER_ANDROID
ThreadState *cur_thread();
void set_cur_thread(ThreadState *thr);
void cur_thread_finalize();
inline void cur_thread_init() { }
#else
__attribute__((tls_model("initial-exec")))
extern THREADLOCAL char cur_thread_placeholder[];
inline ThreadState *cur_thread() {
  return reinterpret_cast<ThreadState *>(cur_thread_placeholder)->current;
}
inline void cur_thread_init() {
  ThreadState *thr = reinterpret_cast<ThreadState *>(cur_thread_placeholder);
  if (UNLIKELY(!thr->current))
    thr->current = thr;
}
inline void set_cur_thread(ThreadState *thr) {
  reinterpret_cast<ThreadState *>(cur_thread_placeholder)->current = thr;
}
inline void cur_thread_finalize() { }
#endif  // SANITIZER_MAC || SANITIZER_ANDROID
#endif  // SANITIZER_GO

class ThreadContext final : public ThreadContextBase {
 public:
  explicit ThreadContext(Tid tid);
  ~ThreadContext();
  ThreadState *thr;
  StackID creation_stack_id;
  VectorClock* sync;
  //Semaphore reset_sema;
  VarSizeStackTrace startStack;
  MutexSet startMutexSet;

  // Override superclass callbacks.
  void OnDead() override;
  void OnJoined(void *arg) override;
  void OnFinished() override;
  void OnStarted(void *arg) override;
  void OnCreated(void *arg) override;
  void OnReset() override;
  void OnDetached(void *arg) override;
};

MD5Hash md5_hash(const void *data, uptr size);

struct RacyStacks {
  MD5Hash hash[2];
  bool operator==(const RacyStacks &other) const;
};

struct RacyAddress {
  uptr addr_min;
  uptr addr_max;
};

struct FiredSuppression {
  ReportType type;
  uptr pc_or_addr;
  Suppression *supp;
};

struct Context {
  Context();

  bool initialized;
#if !SANITIZER_GO
  bool after_multithreaded_fork;
#endif

  MetaMap metamap;

  Mutex report_mtx;
  int nreported;
  int nmissed_expected;
  atomic_uint64_t last_symbolize_time_ns;

  void *background_thread;
  atomic_uint32_t stop_background_thread;

  ThreadRegistry thread_registry;

  Mutex racy_mtx;
  Vector<RacyStacks> racy_stacks;
  Vector<RacyAddress> racy_addresses;
  // Number of fired suppressions may be large enough.
  Mutex fired_suppressions_mtx;
  InternalMmapVector<FiredSuppression> fired_suppressions;
  DDetector *dd;

  Flags flags;

  Mutex slot_mtx;
  TidSlot slots[kMaxSid - 1];
  TidSlot* free_slot_head;
  TidSlot* free_slot_tail;
  atomic_sint32_t reset_pending;
  //atomic_sint32_t reset_scheduled;

  Mutex trace_part_mtx;
  TracePart* trace_part_cache;
  u32 trace_part_count;

  u64 stat[StatCnt];
};

extern Context *ctx;  // The one and the only global runtime context.

ALWAYS_INLINE Flags *flags() {
  return &ctx->flags;
}

struct ScopedIgnoreInterceptors {
  ScopedIgnoreInterceptors() {
#if !SANITIZER_GO
    cur_thread()->ignore_interceptors++;
#endif
  }

  ~ScopedIgnoreInterceptors() {
#if !SANITIZER_GO
    cur_thread()->ignore_interceptors--;
#endif
  }
};

struct ExternalCallback {
  ExternalCallback();
  ~ExternalCallback();
};

const char *GetObjectTypeFromTag(uptr tag);
const char *GetReportHeaderFromTag(uptr tag);
uptr TagFromShadowStackFrame(uptr pc);

class ReportScope {
 public:
  ReportScope();
  ReportScope(const ReportScope&) = delete;

 private:
  ThreadRegistryLock registry_lock_;
  Lock slot_lock_;
  Lock report_lock_;
  ScopedErrorReportLock error_lock_;
};

bool ShouldReport(ThreadState *thr, ReportType typ);
ThreadContext *IsThreadStackOrTls(uptr addr, bool *is_stack);
void RestoreStack(EventType type, Sid sid, Epoch epoch, uptr addr, uptr size, bool isRead, bool isAtomic, bool isFreed, Tid* ptid, VarSizeStackTrace *stk,
                  MutexSet *mset, uptr *tag = nullptr);

// The stack could look like:
//   <start> | <main> | <foo> | tag | <bar>
// This will extract the tag and keep:
//   <start> | <main> | <foo> | <bar>
template<typename StackTraceTy>
void ExtractTagFromStack(StackTraceTy *stack, uptr *tag = nullptr) {
  if (stack->size < 2) return;
  uptr possible_tag_pc = stack->trace[stack->size - 2];
  uptr possible_tag = TagFromShadowStackFrame(possible_tag_pc);
  if (possible_tag == kExternalTagNone) return;
  stack->trace_buffer[stack->size - 2] = stack->trace_buffer[stack->size - 1];
  stack->size -= 1;
  if (tag) *tag = possible_tag;
}

template<typename StackTraceTy>
void ObtainCurrentStack(ThreadState *thr, uptr toppc, StackTraceTy *stack,
                        uptr *tag = nullptr) {
  uptr size = thr->shadow_stack_pos - thr->shadow_stack;
  uptr start = 0;
  if (size + !!toppc > kStackTraceMax) {
    start = size + !!toppc - kStackTraceMax;
    size = kStackTraceMax - !!toppc;
  }
  stack->Init(&thr->shadow_stack[start], size, toppc);
  ExtractTagFromStack(stack, tag);
}

#define GET_STACK_TRACE_FATAL(thr, pc) \
  VarSizeStackTrace stack; \
  ObtainCurrentStack(thr, pc, &stack); \
  stack.ReverseOrder();

#if TSAN_COLLECT_STATS
void StatAggregate(u64 *dst, u64 *src);
void StatOutput(u64 *stat);
#endif

void ALWAYS_INLINE StatInc(ThreadState *thr, StatType typ, u64 n = 1) {
#if TSAN_COLLECT_STATS
  thr->stat[typ] += n;
#endif
}
void ALWAYS_INLINE StatSet(ThreadState *thr, StatType typ, u64 n) {
#if TSAN_COLLECT_STATS
  thr->stat[typ] = n;
#endif
}

void MapShadow(uptr addr, uptr size);
void MapThreadTrace(uptr addr, uptr size, const char *name);
void DontNeedShadowFor(uptr addr, uptr size);
void UnmapShadow(ThreadState *thr, uptr addr, uptr size);
void InitializeShadowMemory();
void InitializeInterceptors();
void InitializeLibIgnore();
void InitializeDynamicAnnotations();

void ForkBefore(ThreadState *thr, uptr pc);
void ForkParentAfter(ThreadState *thr, uptr pc);
void ForkChildAfter(ThreadState *thr, uptr pc);

void ReportRace(ThreadState *thr, RawShadow* shadow_mem, Shadow cur, Shadow old);
bool OutputReport(ThreadState *thr, ReportDesc* rep);
bool IsFiredSuppression(Context *ctx, ReportType type, StackTrace trace);
bool IsExpectedReport(uptr addr, uptr size);
void PrintMatchedBenignRaces();

#if 1
#if defined(TSAN_DEBUG_OUTPUT) && TSAN_DEBUG_OUTPUT >= 1
# define DPrintf Printf
#else
# define DPrintf(...) do {} while(0)
#endif

#if defined(TSAN_DEBUG_OUTPUT) && TSAN_DEBUG_OUTPUT >= 2
# define DPrintf2 Printf
#else
# define DPrintf2(...) do {} while(0)
#endif

#else
# define DPrintf Printf
//# define DPrintf2 Printf
# define DPrintf2(...) do {} while(0)
#endif

StackID CurrentStackId(ThreadState *thr, uptr pc);
void PrintCurrentStack(ThreadState *thr, uptr pc);
void PrintCurrentStackSlow(uptr pc);  // uses libunwind
void PrintStack(StackTrace stack);
void PrintStack(StackID id);

void Initialize(ThreadState *thr);
void MaybeSpawnBackgroundThread();
int Finalize(ThreadState *thr);

void OnUserAlloc(ThreadState *thr, uptr pc, uptr p, uptr sz, bool write);
void OnUserFree(ThreadState *thr, uptr pc, uptr p, bool write);

template<bool kInRuntime = true>
void MemoryAccess(ThreadState *thr, uptr pc, uptr addr,
    u32 kAccessSizeLog, bool kAccessIsWrite, bool kIsAtomic);
void MemoryAccessImpl(ThreadState *thr, uptr addr,
    u32 kAccessSizeLog, bool kAccessIsWrite, bool kIsAtomic,
    RawShadow *shadow_mem, Shadow cur);
void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr,
    uptr size, bool is_write);
void UnalignedMemoryAccess(ThreadState *thr, uptr pc, uptr addr,
    int size, bool kAccessIsWrite, bool kIsAtomic);

void ALWAYS_INLINE MemoryRead(ThreadState *thr, uptr pc,
                                     uptr addr, int kAccessSizeLog) {
  MemoryAccess(thr, pc, addr, kAccessSizeLog, false, false);
}

void ALWAYS_INLINE MemoryWrite(ThreadState *thr, uptr pc,
                                      uptr addr, int kAccessSizeLog) {
  MemoryAccess(thr, pc, addr, kAccessSizeLog, true, false);
}

void ALWAYS_INLINE MemoryReadAtomic(ThreadState *thr, uptr pc,
                                           uptr addr, int kAccessSizeLog) {
  MemoryAccess(thr, pc, addr, kAccessSizeLog, false, true);
}

void ALWAYS_INLINE MemoryWriteAtomic(ThreadState *thr, uptr pc,
                                            uptr addr, int kAccessSizeLog) {
  MemoryAccess(thr, pc, addr, kAccessSizeLog, true, true);
}

void MemoryResetRange(ThreadState *thr, uptr pc, uptr addr, uptr size);
void MemoryRangeFreed(ThreadState *thr, uptr pc, uptr addr, uptr size);
void MemoryRangeImitateWrite(ThreadState *thr, uptr pc, uptr addr, uptr size);
void MemoryRangeImitateWriteOrReset(ThreadState *thr, uptr pc, uptr addr,
                                         uptr size);

void MBlockAlloc(ThreadState *thr, uptr pc, uptr p, uptr sz);
uptr MBlockFree(ThreadState *thr, uptr pc, uptr p);

void ThreadIgnoreBegin(ThreadState *thr, uptr pc, bool save_stack = true);
void ThreadIgnoreEnd(ThreadState *thr, uptr pc);
void ThreadIgnoreSyncBegin(ThreadState *thr, uptr pc, bool save_stack = true);
void ThreadIgnoreSyncEnd(ThreadState *thr, uptr pc);

template<bool kInRuntime = true>
void FuncEntry(ThreadState *thr, uptr pc);
template<bool kInRuntime = true>
void FuncExit(ThreadState *thr);

Tid ThreadCreate(ThreadState *thr, uptr pc, uptr uid, bool detached);
void ThreadStart(ThreadState *thr, Tid tid, tid_t os_id,
                 ThreadType thread_type);
void ThreadFinish(ThreadState *thr);
Tid ThreadConsumeTid(ThreadState *thr, uptr pc, uptr uid);
void ThreadJoin(ThreadState *thr, uptr pc, Tid tid);
void ThreadDetach(ThreadState *thr, uptr pc, Tid tid);
void ThreadFinalize(ThreadState *thr);
void ThreadSetName(ThreadState *thr, const char *name);
int ThreadCount(ThreadState *thr);
void ProcessPendingSignals(ThreadState *thr);
void ThreadNotJoined(ThreadState *thr, uptr pc, Tid tid, uptr uid);

Processor *ProcCreate();
void ProcDestroy(Processor *proc);
void ProcWire(Processor *proc, ThreadState *thr);
void ProcUnwire(Processor *proc, ThreadState *thr);

// Note: the parameter is called flagz, because flags is already taken
// by the global function that returns flags.
void MutexCreate(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
void MutexDestroy(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
void MutexPreLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
void MutexPostLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0,
    int rec = 1);
int  MutexUnlock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
void MutexPreReadLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
void MutexPostReadLock(ThreadState *thr, uptr pc, uptr addr, u32 flagz = 0);
void MutexReadUnlock(ThreadState *thr, uptr pc, uptr addr);
void MutexReadOrWriteUnlock(ThreadState *thr, uptr pc, uptr addr);
void MutexRepair(ThreadState *thr, uptr pc, uptr addr);  // call on EOWNERDEAD
void MutexInvalidAccess(ThreadState *thr, uptr pc, uptr addr);

void Acquire(ThreadState *thr, uptr pc, uptr addr);
// AcquireGlobal synchronizes the current thread with all other threads.
// In terms of happens-before relation, it draws a HB edge from all threads
// (where they happen to execute right now) to the current thread. We use it to
// handle Go finalizers. Namely, finalizer goroutine executes AcquireGlobal
// right before executing finalizers. This provides a coarse, but simple
// approximation of the actual required synchronization.
void AcquireGlobal(ThreadState *thr, uptr pc);
void Release(ThreadState *thr, uptr pc, uptr addr);
void ReleaseStoreAcquire(ThreadState *thr, uptr pc, uptr addr);
void ReleaseStore(ThreadState *thr, uptr pc, uptr addr);
void AfterSleep(ThreadState *thr, uptr pc);
void AcquireImpl(ThreadState *thr, uptr pc, const VectorClock *c);
void ReleaseImpl(ThreadState *thr, uptr pc, VectorClock **c);
void ReleaseStoreAcquireImpl(ThreadState *thr, uptr pc, VectorClock **c);
void ReleaseStoreImpl(ThreadState *thr, uptr pc, VectorClock **c);
void ReleaseAcquireImpl(ThreadState *thr, uptr pc, VectorClock **c);
void IncrementEpoch(ThreadState *thr, uptr pc);

void TraceSwitch(ThreadState *thr);

template<typename EventT>
ALWAYS_INLINE WARN_UNUSED_RESULT
bool TraceAcquire(ThreadState *thr, EventT** ev) {
  CheckNoLocks();
  DCHECK(thr->slot);
  StatInc(thr, StatEvents);
  Event* pos = (Event*)atomic_load_relaxed(&thr->trace_pos);
  // TracePart is allocated with mmap and is at least 4K aligned.
  // So the following check is a faster way to check for part end.
  // It may have false positives in the middle of the trace,
  // they are filtered out in TraceSwitch.
  if (UNLIKELY(((uptr)(pos + 1) & 0xff0) == 0))
    return false;
  *ev = reinterpret_cast<EventT*>(pos);
  return true;
}

template<typename EventT>
ALWAYS_INLINE
void TraceRelease(ThreadState *thr, EventT* evp) {
  DCHECK_LE(evp + 1, &thr->slot->trace.current->events[TracePart::kSize]);
  atomic_store_relaxed(&thr->trace_pos, (uptr)(evp + 1));
}

template<typename EventT>
void TraceEvent(ThreadState *thr, EventT ev) {
  EventT* evp;
  if (!TraceAcquire(thr, &evp)) {
    TraceSwitch(thr);
    bool res = TraceAcquire(thr, &evp);
    DCHECK(res);
    (void)res;
  }
  *evp = ev;
  TraceRelease(thr, evp);
}

void TraceMemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size, bool isRead, bool isFreed);
void TraceMutexLock(ThreadState *thr, EventType type, uptr pc, uptr addr, StackID stk);
void TraceMutexUnlock(ThreadState *thr, uptr addr);
void TraceRelease(ThreadState *thr);
void TraceSlotAttach(ThreadState *thr);

#if !SANITIZER_GO
ALWAYS_INLINE uptr HeapEnd() {
  return HeapMemEnd() + PrimaryAllocator::AdditionalSize();
}
#endif

void SlotAttach(ThreadState *thr);
void SlotDetach(ThreadState *thr);
void ThreadPreempt(ThreadState *thr);
bool HandlePreemptSignal(ThreadState *thr, int sig, void* info, void* ctx);
void CompleteReset(ThreadState *thr);
ALWAYS_INLINE void CheckReset(ThreadState *thr) {
  if (UNLIKELY(atomic_load_relaxed(&ctx->reset_pending)))
    CompleteReset(thr);
}
extern void* flat_funcs[];

ThreadState *FiberCreate(ThreadState *thr, uptr pc, unsigned flags);
void FiberDestroy(ThreadState *thr, uptr pc, ThreadState *fiber);
void FiberSwitch(ThreadState *thr, uptr pc, ThreadState *fiber, unsigned flags);

struct ScopedRuntime {
  ScopedRuntime(ThreadState* thr) : thr_(thr) {
    Enter(thr_);
  }
  ~ScopedRuntime() {
    Leave(thr_);
  }
  ThreadState* thr_;
  
  static void Enter(ThreadState* thr) {
    //!!! CheckNoLocks();
    int v = atomic_load_relaxed(&thr->in_runtime);
    CHECK_EQ(v, 0);  //!!!
    atomic_store_relaxed(&thr->in_runtime, v + 1);
    atomic_signal_fence(memory_order_seq_cst);
  }
  
  static void Leave(ThreadState* thr) {
    //!!! CheckNoLocks();
    atomic_signal_fence(memory_order_seq_cst);
    int v = atomic_load_relaxed(&thr->in_runtime);
    CHECK_EQ(v, 1); //!!!
    atomic_store_relaxed(&thr->in_runtime, v - 1);
    atomic_signal_fence(memory_order_seq_cst);
    if (UNLIKELY(atomic_load_relaxed(&thr->reset_pending)))
      //!!! the thread may not own slow anymore (just finished).
      CompleteReset(thr);
  }
};

template<bool kInRuntime>
struct MaybeScopedRuntime : ScopedRuntime {
  MaybeScopedRuntime(ThreadState* thr) : ScopedRuntime(thr) {}  
};

template<>
struct MaybeScopedRuntime<true> {
  MaybeScopedRuntime(ThreadState* thr) {}  
};

/*
ALWAYS_INLINE
void RtMemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size, bool is_write) {
  ScopedRuntime rt(thr);
  MemoryAccessRange(thr, pc, addr, size, is_write);
}
*/

ALWAYS_INLINE
void RtMemoryRead(ThreadState *thr, uptr pc, uptr addr, int kAccessSizeLog) {
  ScopedRuntime rt(thr);
  MemoryAccess(thr, pc, addr, kAccessSizeLog, false, false);
}

ALWAYS_INLINE
void RtMemoryWrite(ThreadState *thr, uptr pc, uptr addr, int kAccessSizeLog) {
  ScopedRuntime rt(thr);
  MemoryAccess(thr, pc, addr, kAccessSizeLog, true, false);
}

#if !SANITIZER_GO
extern void* __tsan_on_initialize;
extern void* __tsan_on_finalize;
#endif

}  // namespace __tsan

#endif  // TSAN_RTL_H
