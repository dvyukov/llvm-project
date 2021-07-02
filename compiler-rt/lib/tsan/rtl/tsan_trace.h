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
#include "tsan_ilist.h"
#include "tsan_mutex.h"
#include "tsan_mutexset.h"
#include "tsan_stack_trace.h"

namespace __tsan {

enum EventType {
  EventTypeAccessEx,
  EventTypeFuncEnter,
  EventTypeFuncExit,
  EventTypeLock,
  EventTypeRLock,
  EventTypeUnlock,
  EventTypeRelease,
};

struct Event {
  u64 isAccess : 1;
  u64 type : 3;
  u64 _ : 60;
};
static_assert(sizeof(Event) == 8, "bad Event size");
static constexpr Event NopEvent = {1, 0, 0};

constexpr uptr kCompressedAddrBits = 44;

struct EventAccess {
  static constexpr uptr kPCBits = 14;

  u64 isAccess : 1;
  u64 isRead : 1;
  u64 isAtomic : 1;
  u64 isExternalPC : 1;
  u64 sizeLog : 2;
  u64 pcDelta : kPCBits;
  u64 addr : kCompressedAddrBits;
};
static_assert(sizeof(EventAccess) == 8, "bad MopEvent size");

struct EventAccessEx {
  static constexpr uptr kSizeLoBits = 12;

  u64 isAccess : 1;
  u64 type : 3;
  u64 isRead : 1;
  u64 isAtomic : 1;
  u64 isFreed : 1;
  u64 isExternalPC : 1;
  u64 sizeLo : kSizeLoBits;
  u64 pc : kCompressedAddrBits;
  u64 addr : kCompressedAddrBits;
  u64 sizeHi : 20;
};
static_assert(sizeof(EventAccessEx) == 16, "bad EventAccessEx size");

struct EventLock {
  static constexpr uptr kStackIDLoBits = 16;

  u64 isAccess : 1;
  u64 type : 3;
  u64 pc : kCompressedAddrBits;
  u64 stackIDLo : kStackIDLoBits;
  u64 stackIDHi : 16;
  u64 isExternalPC : 1;
  u64 _ : 3;
  u64 addr : kCompressedAddrBits;
};
static_assert(sizeof(EventLock) == 16, "bad EventLock size");

struct EventUnlock {
  u64 isAccess : 1;
  u64 type : 3;
  u64 _ : 16;
  u64 addr : kCompressedAddrBits;
};
static_assert(sizeof(EventUnlock) == 8, "bad EventUnlock size");

struct EventPC {
  u64 isAccess : 1;
  u64 type : 3;
  u64 isExternalPC : 1;
  u64 _ : 15;
  u64 pc : kCompressedAddrBits;
};
static_assert(sizeof(EventPC) == 8, "bad EventPC size");

struct TracePart;

struct TraceHeader {
  Trace* trace = nullptr;
  INode trace_parts;
  INode global;
  VarSizeStackTrace start_stack;
  MutexSet start_mset;
  Epoch start_epoch = kEpochZero;
  uptr prev_pc = 0;
#if !SANITIZER_GO
  BufferedStackTrace stack0;  // Start stack for the trace.
#else
  VarSizeStackTrace stack0;
#endif
};

struct TracePart : TraceHeader {
  static constexpr uptr kByteSize = 256 << 10;
  static constexpr uptr kSize =
      (kByteSize - sizeof(TraceHeader)) / sizeof(Event);
  // Note: TracePos assumes this to be the last field.
  Event events[kSize];

  TracePart() {
  }
};
static_assert(sizeof(TracePart) == TracePart::kByteSize, "bad TracePart size");

struct Trace {
  Mutex mtx;
  IList<TraceHeader, &TraceHeader::trace_parts, TracePart> parts;
  Event* final_pos = nullptr;
  uptr parts_allocated = 0;

  Trace() : mtx(MutexTypeTrace) {
  }
};

}  // namespace __tsan

#endif  // TSAN_TRACE_H
