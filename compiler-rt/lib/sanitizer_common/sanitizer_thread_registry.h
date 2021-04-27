//===-- sanitizer_thread_registry.h -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between sanitizer tools.
//
// General thread bookkeeping functionality.
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_THREAD_REGISTRY_H
#define SANITIZER_THREAD_REGISTRY_H

#include "sanitizer_common.h"
#include "sanitizer_list.h"
#include "sanitizer_mutex.h"

namespace __sanitizer {

enum ThreadStatus {
  ThreadStatusInvalid,   // Non-existent thread, data is invalid.
  ThreadStatusCreated,   // Created but not yet running.
  ThreadStatusRunning,   // The thread is currently running.
  ThreadStatusFinished,  // Joinable thread is finished but not yet joined.
  ThreadStatusDead       // Joined, but some info is still available.
};

enum class ThreadType {
  Regular, // Normal thread
  Worker,  // macOS Grand Central Dispatch (GCD) worker thread
  Fiber,   // Fiber
};

// Generic thread context. Specific sanitizer tools may inherit from it.
// If thread is dead, context may optionally be reused for a new thread.
class ThreadContextBase {
 public:
  explicit ThreadContextBase(u32 tid);
  const u32 tid;   // Thread ID. Main thread should have tid = 0.
  tid_t os_id;     // PID (used for reporting).
  uptr user_id;   // Some opaque user thread id (e.g. pthread_t).
  char name[64];  // As annotated by user.

  ThreadStatus status;
  bool detached;
  ThreadType thread_type;

  u32 parent_tid;

  atomic_uint32_t thread_destroyed; // To address race of Joined vs Finished

  void SetName(const char *new_name);

  void SetDead();
  void SetJoined(void *arg);
  void SetFinished();
  void SetStarted(tid_t _os_id, ThreadType _thread_type, void *arg);
  void SetCreated(uptr _user_id, bool _detached, u32 _parent_tid, void *arg);
  void Reset();

  void SetDestroyed();
  bool GetDestroyed();

  // The following methods may be overriden by subclasses.
  // Some of them take opaque arg that may be optionally be used
  // by subclasses.
  virtual void OnDead() {}
  virtual void OnJoined(void *arg) {}
  virtual void OnFinished() {}
  virtual void OnStarted(void *arg) {}
  virtual void OnCreated(void *arg) {}
  virtual void OnReset() {}
  virtual void OnDetached(void *arg) {}

 protected:
  ~ThreadContextBase();
};

typedef ThreadContextBase *(*ThreadContextFactory)(u32 tid);

class MUTEX ThreadRegistry {
 public:
  ThreadRegistry(ThreadContextFactory factory);

  void Lock() ACQUIRE() { mtx_.Lock(); }
  void CheckLocked() const CHECK_LOCKED() { mtx_.CheckLocked(); }
  void Unlock() RELEASE() { mtx_.Unlock(); }

  // Should be guarded by ThreadRegistryLock.
  ThreadContextBase *GetThreadLocked(u32 tid) {
    return threads_.empty() ? nullptr : threads_[tid];
  }

  //!!! Remove
  u32 NumThreadsLocked() const { return TotalThreads(); }

  u32 CreateThread(uptr user_id, bool detached, u32 parent_tid, void *arg);

  typedef void (*ThreadCallback)(ThreadContextBase *tctx, void *arg);
  // Invokes callback with a specified arg for each thread context.
  // Should be guarded by ThreadRegistryLock.
  void RunCallbackForEachThreadLocked(ThreadCallback cb, void *arg);

  typedef bool (*FindThreadCallback)(ThreadContextBase *tctx, void *arg);
  // Finds a thread using the provided callback. Returns kInvalidTid if no
  // thread is found.
  u32 FindThread(FindThreadCallback cb, void *arg);
  // Should be guarded by ThreadRegistryLock. Return 0 if no thread
  // is found.
  ThreadContextBase *FindThreadContextLocked(FindThreadCallback cb,
                                             void *arg);
  ThreadContextBase *FindThreadContextByOsIDLocked(tid_t os_id);

  void SetThreadName(u32 tid, const char *name);
  void SetThreadNameByUserId(uptr user_id, const char *name);
  void DetachThread(u32 tid, void *arg);
  void JoinThread(u32 tid, void *arg);
  // Finishes thread and returns previous status.
  ThreadStatus FinishThread(u32 tid);
  void StartThread(u32 tid, tid_t os_id, ThreadType thread_type, void *arg);
  void SetThreadUserId(u32 tid, uptr user_id);

  u32 TotalThreads() const { return atomic_load_relaxed(&total_threads_); }
  u32 RunningThreads() const { return atomic_load_relaxed(&running_threads_); }

 private:
  const ThreadContextFactory context_factory_;

  Mutex mtx_;
  InternalMmapVector<ThreadContextBase *> threads_;
  atomic_uint32_t total_threads_;
  atomic_uint32_t running_threads_;
};

typedef GenericScopedLock<ThreadRegistry> ThreadRegistryLock;

} // namespace __sanitizer

#endif // SANITIZER_THREAD_REGISTRY_H
