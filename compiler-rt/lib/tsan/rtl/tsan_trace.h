//===-- tsan_trace.h --------------------------------------------*- C++ -*-===//
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
#ifndef TSAN_TRACE_H
#define TSAN_TRACE_H

#include "tsan_defs.h"
#include "tsan_mutex.h"
#include "tsan_stack_trace.h"
#include "tsan_mutexset.h"

namespace __tsan {

enum EventType {
  EventTypeAccessEx,
  EventTypeFuncEnter,
  EventTypeFuncExit,
  EventTypeLock,
  EventTypeRLock,
  EventTypeUnlock,
  EventTypeRelease,
  EventTypeAttach,
};

struct Event {
  u64 isAccess : 1;
  u64 type : 3;
  u64 _: 60;
};
static_assert(sizeof(Event) == 8, "bad Event size");
static constexpr Event NopEvent = {1, 0, 0};

struct EventAccess {
  u64 isAccess : 1;
  u64 isRead : 1;
  u64 isAtomic: 1;
  u64 isExternalPC: 1;
  u64 sizeLog: 2;
  u64 pcDelta : 15;
  u64 addr : 43;
};
static_assert(sizeof(EventAccess) == 8, "bad MopEvent size");

struct EventAccessEx {
  u64 isAccess: 1;
  u64 type: 3;
  u64 isRead : 1;
  u64 isAtomic: 1;
  u64 isFreed: 1;
  u64 isExternalPC: 1;
  u64 sizeLo: 13;
  u64 pc : 43;
  u64 isNotAccess: 1; //!!! do we need this?
  u64 addr : 43;
  u64 sizeHi: 20;
};
static_assert(sizeof(EventAccessEx) == 16, "bad EventAccessEx size");

struct EventLock {
  u64 isAccess: 1;
  u64 type: 3;
  u64 isExternalPC: 1;
  u64 pc : 43;
  u64 stackIDLo: 16;
  u64 stackIDHi: 16;
  u64 _: 5;
  u64 addr : 43;
};  
static_assert(sizeof(EventLock) == 16, "bad EventLock size");

struct EventUnlock {
  u64 isAccess: 1;
  u64 type: 3;
  u64 _: 17;
  u64 addr : 43;
};  
static_assert(sizeof(EventUnlock) == 8, "bad EventUnlock size");

struct EventPC {
  u64 isAccess: 1;
  u64 type: 3;
  u64 isExternalPC: 1;
  u64 _: 16;
  u64 pc : 43;
};  
static_assert(sizeof(EventPC) == 8, "bad EventPC size");

struct EventAttach {
  u64 isAccess: 1;
  u64 type: 3;
  u64 _: 28;
  u64 tid: 32;
};  
static_assert(sizeof(EventAttach) == 8, "bad EventPC size");

struct TracePart {
  TracePart* next;
  static constexpr uptr kSize = 511;
  // Note: TracePos assumes this to be the last field.
  Event events[kSize];
};
static_assert(sizeof(TracePart) == (4 << 10), "bad TracePart size");

struct Trace {
  Mutex mtx;
  TracePart* first = nullptr;
  TracePart* current = nullptr;
  Event* pos = nullptr;
  uptr prev_pc = 0;

  Trace()
    : mtx(MutexTypeTrace) {
  }
};

}  // namespace __tsan

#endif  // TSAN_TRACE_H
