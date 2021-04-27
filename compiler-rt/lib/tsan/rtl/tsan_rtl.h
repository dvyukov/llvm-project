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

void CheckFailed(const char *file, int line, const char *cond,
                     u64 v1, u64 v2);

class Shadow {
 public:
  explicit Shadow(RawShadow x = 0) {
    raw_ = x;
  }

  RawShadow raw() const {
    return raw_;
  }

  Sid sid() const {
    return sid_;
  }

  void SetSid(Sid sid) {
    sid_ = sid;
  }

  Epoch epoch() const {
    return epoch_;
  }

  void SetEpoch(Epoch epoch) {
    epoch_ = epoch;
  }

  void SetAccess(uptr addr, int sizeLog, bool isRead, bool isAtomic) {
    addr0_ = addr;
    size_log_ = sizeLog;
    is_freed_ = 0;
    is_atomic_ = isAtomic;
    is_read_ = isRead;
 }

  void SetAddr0AndSizeLog(u64 addr0, unsigned kAccessSizeLog) {
    DCHECK_EQ(addr0_, 0);
    DCHECK_EQ(size_log_, 0);
    DCHECK_LE(addr0, 7);
    DCHECK_LE(kAccessSizeLog, 3);
    addr0_ = addr0;
    size_log_ = kAccessSizeLog;
  }

  void SetWrite(unsigned kAccessIsWrite) {
    DCHECK(!is_read_);
    if (!kAccessIsWrite)
      is_read_ = true;
  }

  void SetAtomic(bool kIsAtomic) {
    DCHECK(!is_atomic_);
    if (kIsAtomic)
      is_atomic_ = true;
  }

  bool IsAtomic() const {
    return is_atomic_;
  }

  bool IsZero() const {
    return raw_ == 0;
  }

  static inline bool SidsAreEqual(const Shadow s1, const Shadow s2) {
    return s1.sid_ == s2.sid_;
  }

  static ALWAYS_INLINE
  bool Addr0AndSizeAreEqual(const Shadow s1, const Shadow s2) {
    return s1.addr0_ == s2.addr0_ && s1.size_log_ == s2.size_log_;
  }

  static ALWAYS_INLINE bool TwoRangesIntersect(Shadow s1, Shadow s2) {
    if (s1.addr0() == s2.addr0()) return true;
    if (s1.addr0() < s2.addr0() && s1.addr0() + s1.size() > s2.addr0())
      return true;
    if (s2.addr0() < s1.addr0() && s2.addr0() + s2.size() > s1.addr0())
      return true;
    return false;
  }

  u64 ALWAYS_INLINE addr0() const { return addr0_; }
  u64 ALWAYS_INLINE size() const { return 1ull << size_log_; }
  bool ALWAYS_INLINE IsWrite() const { return !IsRead(); }
  bool ALWAYS_INLINE IsRead() const { return is_read_; }

  void MarkAsFreed() {
    DCHECK(!is_freed_);
    is_freed_ = true;
  }

  bool IsFreed() const {
    return is_freed_;
  }

  bool ALWAYS_INLINE IsBothReadsOrAtomic(bool kIsWrite, bool kIsAtomic) const {
    return (!IsWrite() && !kIsWrite) || (IsAtomic() && kIsAtomic);
  }

  bool ALWAYS_INLINE IsRWWeakerOrEqual(bool kIsWrite, bool kIsAtomic) const {
    return (IsAtomic() > kIsAtomic) ||
        (IsAtomic() == kIsAtomic && !IsWrite() >= !kIsWrite);
  }

 private:
  union {
    struct {
      Sid sid_;
      u8 is_freed_: 1;
      u8 is_atomic_: 1;
      u8 is_read_: 1;
      u8 size_log_: 2;
      u8 addr0_: 3;
      Epoch epoch_;
    };
    RawShadow raw_;
  };
};
static_assert(sizeof(Shadow) == kShadowSize, "bad Shadow size");

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
struct Processor {
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

struct TidSlot {
  Sid sid;
  ThreadState* thr;
  bool reset_wait;
  bool dirty;
  VectorClock clock;
  Trace trace;
};

// This struct is stored in TLS.
struct ThreadState {
  Shadow fast_state;
  bool ignore_enabled_;

  uptr *shadow_stack_pos;
  uptr *shadow_stack_end;

  Event* trace_pos;
  uptr trace_prev_pc;

  // Technically `current` should be a separate THREADLOCAL variable;
  // but it is placed here in order to share cache line with previous fields.
  ThreadState* current;

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
  RawShadow *racy_shadow_addr;
  Shadow racy_state[2];
  MutexSet mset;
  VectorClock clock;
  bool need_epoch_increment;
#if !SANITIZER_GO
  Vector<JmpBuf> jmp_bufs;
  int ignore_interceptors;
  int range_access_race;
  bool range_race;
  bool in_symbolizer;
  bool in_ignored_lib;
  bool is_inited;
  bool is_dead;
#endif
#if TSAN_COLLECT_STATS
  u64 stat[StatCnt];
#endif
  const Tid tid;
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

  TidSlot slots[kMaxSid];
  atomic_sint32_t reset_pending;
  atomic_sint32_t reset_scheduled;

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

const char *GetObjectTypeFromTag(uptr tag);
const char *GetReportHeaderFromTag(uptr tag);
uptr TagFromShadowStackFrame(uptr pc);

class ScopedReportBase {
 public:
  void AddMemoryAccess(uptr addr, uptr external_tag, Shadow s, Tid tid, StackTrace stack,
                       const MutexSet *mset);
  void AddStack(StackTrace stack, bool suppressable = false);
  void AddThread(const ThreadContext *tctx, bool suppressable = false);
  void AddThread(Tid unique_tid, bool suppressable = false);
  void AddUniqueTid(Tid unique_tid);
  int AddMutex(uptr addr, StackID creation_stack_id);
  void AddLocation(uptr addr, uptr size);
  void AddSleep(StackID stack_id);
  void SetCount(int count);

  const ReportDesc *GetReport() const;

 protected:
  ScopedReportBase(ReportType typ, uptr tag);
  ~ScopedReportBase();

 private:
  ReportDesc *rep_;
  // Symbolizer makes lots of intercepted calls. If we try to process them,
  // at best it will cause deadlocks on internal mutexes.
  ScopedIgnoreInterceptors ignore_interceptors_;

  ScopedReportBase(const ScopedReportBase &) = delete;
  void operator=(const ScopedReportBase &) = delete;
};

class ScopedReport : public ScopedReportBase {
 public:
  explicit ScopedReport(ReportType typ, uptr tag = kExternalTagNone);
  ~ScopedReport();

 private:
  ScopedErrorReportLock lock_;
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

void ReportRace(ThreadState *thr);
bool OutputReport(ThreadState *thr, const ScopedReport &srep);
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
# define DPrintf2 Printf
#endif

StackID CurrentStackId(ThreadState *thr, uptr pc);
ReportStack *SymbolizeStackId(StackID stack_id);
void PrintCurrentStack(ThreadState *thr, uptr pc);
void PrintCurrentStackSlow(uptr pc);  // uses libunwind

void Initialize(ThreadState *thr);
void MaybeSpawnBackgroundThread();
int Finalize(ThreadState *thr);

void OnUserAlloc(ThreadState *thr, uptr pc, uptr p, uptr sz, bool write);
void OnUserFree(ThreadState *thr, uptr pc, uptr p, bool write);

void MemoryAccess(ThreadState *thr, uptr pc, uptr addr,
    int kAccessSizeLog, bool kAccessIsWrite, bool kIsAtomic);
void MemoryAccessImpl(ThreadState *thr, uptr addr,
    int kAccessSizeLog, bool kAccessIsWrite, bool kIsAtomic,
    RawShadow *shadow_mem, Shadow cur);
void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr,
    uptr size, bool is_write);
void MemoryAccessRangeStep(ThreadState *thr, uptr pc, uptr addr,
    uptr size, uptr step, bool is_write);
void UnalignedMemoryAccess(ThreadState *thr, uptr pc, uptr addr,
    int size, bool kAccessIsWrite, bool kIsAtomic);

const int kSizeLog1 = 0;
const int kSizeLog2 = 1;
const int kSizeLog4 = 2;
const int kSizeLog8 = 3;

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
void MemoryRangeImitateWriteOrResetRange(ThreadState *thr, uptr pc, uptr addr,
                                         uptr size);

void ThreadIgnoreBegin(ThreadState *thr, uptr pc, bool save_stack = true);
void ThreadIgnoreEnd(ThreadState *thr, uptr pc);
void ThreadIgnoreSyncBegin(ThreadState *thr, uptr pc, bool save_stack = true);
void ThreadIgnoreSyncEnd(ThreadState *thr, uptr pc);

void FuncEntry(ThreadState *thr, uptr pc);
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

// The hacky call uses custom calling convention and an assembly thunk.
// It is considerably faster that a normal call for the caller
// if it is not executed (it is intended for slow paths from hot functions).
// The trick is that the call preserves all registers and the compiler
// does not treat it as a call.
// If it does not work for you, use normal call.
#if !SANITIZER_DEBUG && defined(__x86_64__) && !SANITIZER_MAC
// The caller may not create the stack frame for itself at all,
// so we create a reserve stack frame for it (1024b must be enough).
#define HACKY_CALL(f) \
  __asm__ __volatile__("sub $1024, %%rsp;" \
                       CFI_INL_ADJUST_CFA_OFFSET(1024) \
                       ".hidden " #f "_thunk;" \
                       "call " #f "_thunk;" \
                       "add $1024, %%rsp;" \
                       CFI_INL_ADJUST_CFA_OFFSET(-1024) \
                       ::: "memory", "cc");
#else
#define HACKY_CALL(f) f()
#endif

void TraceSwitch(ThreadState *thr);

extern "C" void __tsan_trace_switch();

template<typename EventT>
ALWAYS_INLINE EventT* TracePos(ThreadState *thr) {
  StatInc(thr, StatEvents);
  Event* pos = thr->trace_pos;
  // TracePart is allocated with mmap and is at least 4K aligned.
  // So the following check is a faster way to check for part end.
  // It may have false positives in the middle of the trace,
  // they are filtered out in TraceSwitch.
  if (UNLIKELY(((uptr)(pos + 1) & 0xff0) == 0)) {
#if !SANITIZER_GO
    HACKY_CALL(__tsan_trace_switch);
#else
    TraceSwitch(thr);
#endif
    pos = thr->trace_pos;
  }
  thr->trace_pos = pos + sizeof(EventT) / sizeof(thr->trace_pos[0]);
  return reinterpret_cast<EventT*>(pos);
}

ALWAYS_INLINE void TraceAddMemoryAccess(ThreadState *thr, uptr pc, uptr addr, uptr sizeLog, bool isRead, bool isAtomic) {
  if (!kCollectHistory)
    return;
  uptr pcDelta = pc - thr->trace_prev_pc + (1<<14);
  thr->trace_prev_pc = pc;
  auto ev = TracePos<EventAccess>(thr);
  if (LIKELY(pcDelta < (1<<15))) {
    ev->isAccess = 1; //!!! if we use 0, does it make code more efficient?
    ev->isRead = isRead;
    ev->isAtomic = isAtomic;
    ev->isExternalPC = 0; //!!!
    ev->sizeLog = sizeLog;
    ev->pcDelta = pcDelta;
    DCHECK_EQ(ev->pcDelta, pcDelta);
    ev->addr = addr;
    return;
  }
  auto evex = reinterpret_cast<EventAccessEx*>(ev);
  thr->trace_pos += (sizeof(*evex) - sizeof(*ev)) / sizeof(EventAccess);
  evex->isAccess = 0;
  evex->type = EventTypeAccessEx;
  evex->isRead = isRead;
  evex->isAtomic = isAtomic;
  evex->isFreed = 0;
  evex->isExternalPC = 0; //!!!
  evex->sizeLo = 1<<sizeLog;
  evex->pc = pc;
  evex->isNotAccess = 0;
  evex->addr = addr;
  evex->sizeHi = 0;
}

ALWAYS_INLINE void TraceAddMemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size, bool isRead, bool isFreed) {
  if (!kCollectHistory)
    return;
  thr->trace_prev_pc = pc;
  auto ev = TracePos<EventAccessEx>(thr);
  ev->isAccess = 0;
  ev->type = EventTypeAccessEx;
  ev->isRead = isRead;
  ev->isAtomic = 0;
  ev->isFreed = isFreed;
  ev->isExternalPC = 0; //!!!
  ev->sizeLo = size;
  ev->pc = pc;
  ev->isNotAccess = 0;
  ev->addr = addr;
  ev->sizeHi = size >> 13;
  //!!! CHECK_EQ(ev->sizeLo + (ev->sizeHi << 13), size);
}

ALWAYS_INLINE void TraceMutexLock(ThreadState *thr, EventType type, uptr pc, uptr addr, StackID stk) {
  DCHECK(type == EventTypeLock || type == EventTypeRLock);
  if (!kCollectHistory)
    return;
  //!!! should these events set trace_prev_pc as well?
  auto ev = TracePos<EventLock>(thr);
  ev->isAccess = 0;
  ev->type = type;
  ev->isExternalPC = 0; //!!! handle
  ev->pc = pc;
  ev->stackIDLo = static_cast<u64>(stk);
  ev->stackIDHi = static_cast<u64>(stk) >> 16;
  ev->_ = 0;  
  ev->addr = addr;
}

ALWAYS_INLINE void TraceMutexUnlock(ThreadState *thr, uptr addr) {
  if (!kCollectHistory)
    return;
  auto ev = TracePos<EventUnlock>(thr);
  ev->isAccess = 0;
  ev->type = EventTypeUnlock;
  ev->_ = 0;
  ev->addr = addr;
}

ALWAYS_INLINE void TraceEvent(ThreadState *thr, EventType type, uptr pc = 0) {
  DCHECK(type == EventTypeFuncEnter || type == EventTypeFuncExit || type == EventTypeRelease);
  if (!kCollectHistory)
    return;
  auto ev = TracePos<EventPC>(thr);
  ev->isAccess = 0;
  ev->type = type;
  ev->_ = 0;
  ev->pc = pc;
}

ALWAYS_INLINE void TraceSlotAttach(ThreadState *thr) {
  if (!kCollectHistory)
    return;
  auto ev = TracePos<EventAttach>(thr);
  ev->isAccess = 0;
  ev->type = EventTypeAttach;
  ev->_ = 0;
  ev->tid = static_cast<u64>(thr->tid);
}

#if !SANITIZER_GO
ALWAYS_INLINE uptr HeapEnd() {
  return HeapMemEnd() + PrimaryAllocator::AdditionalSize();
}
#endif

void SlotAttach(ThreadState *thr);
void SlotDetach(ThreadState *thr);
void GlobalReset(ThreadState *thr);
void CompleteReset(ThreadState *thr);
ALWAYS_INLINE void CheckReset(ThreadState *thr) {
  if (UNLIKELY(atomic_load_relaxed(&ctx->reset_pending) ||
      atomic_load_relaxed(&ctx->reset_scheduled)))
    CompleteReset(thr);
}

ThreadState *FiberCreate(ThreadState *thr, uptr pc, unsigned flags);
void FiberDestroy(ThreadState *thr, uptr pc, ThreadState *fiber);
void FiberSwitch(ThreadState *thr, uptr pc, ThreadState *fiber, unsigned flags);

// These need to match __tsan_switch_to_fiber_* flags defined in
// tsan_interface.h. See documentation there as well.
enum FiberSwitchFlags {
  FiberSwitchFlagNoSync = 1 << 0, // __tsan_switch_to_fiber_no_sync
};

}  // namespace __tsan

#endif  // TSAN_RTL_H
