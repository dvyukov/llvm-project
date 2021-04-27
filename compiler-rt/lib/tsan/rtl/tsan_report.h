//===-- tsan_report.h -------------------------------------------*- C++ -*-===//
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
#ifndef TSAN_REPORT_H
#define TSAN_REPORT_H

#include "sanitizer_common/sanitizer_symbolizer.h"
#include "sanitizer_common/sanitizer_thread_registry.h"
#include "sanitizer_common/sanitizer_vector.h"
#include "tsan_defs.h"

namespace __tsan {

enum ReportType {
  ReportTypeRace,
  ReportTypeVptrRace,
  ReportTypeUseAfterFree,
  ReportTypeVptrUseAfterFree,
  ReportTypeExternalRace,
  ReportTypeThreadLeak,
  ReportTypeMutexDestroyLocked,
  ReportTypeMutexDoubleLock,
  ReportTypeMutexInvalidAccess,
  ReportTypeMutexBadUnlock,
  ReportTypeMutexBadReadLock,
  ReportTypeMutexBadReadUnlock,
  ReportTypeSignalUnsafe,
  ReportTypeErrnoInSignal,
  ReportTypeDeadlock
};

struct ReportStack {
  SymbolizedStack *frames;
  bool suppressable;

  ReportStack();
};

struct ReportMopMutex {
  int id;
  bool write;
};

struct ReportMop {
  Tid tid;
  uptr addr;
  int size;
  bool write;
  bool atomic;
  uptr external_tag;
  Vector<ReportMopMutex> mset;
  ReportStack *stack;

  ReportMop();
};

enum ReportLocationType {
  ReportLocationInvalid,
  ReportLocationGlobal,
  ReportLocationHeap,
  ReportLocationStack,
  ReportLocationTLS,
  ReportLocationFD
};

struct ReportLocation {
  ReportLocationType type;
  DataInfo global;
  uptr heap_chunk_start;
  uptr heap_chunk_size;
  uptr external_tag;
  Tid tid;
  int fd;
  bool suppressable;
  ReportStack *stack;

  ReportLocation();
};

struct ReportThread {
  Tid id;
  tid_t os_id;
  bool running;
  ThreadType thread_type;
  char *name;
  Tid parent_tid;
  ReportStack *stack;
};

struct ReportMutex {
  int id;
  uptr addr;
  ReportStack *stack;
};

class ReportDesc {
 public:
  ReportType typ;
  uptr tag;
  Vector<ReportStack*> stacks;
  Vector<ReportMop*> mops;
  Vector<ReportLocation*> locs;
  Vector<ReportMutex*> mutexes;
  Vector<ReportThread*> threads;
  Vector<Tid> unique_tids;
  ReportStack *sleep;
  int count;

  ReportDesc();
  ~ReportDesc();

 private:
  ReportDesc(const ReportDesc&);
  void operator = (const ReportDesc&);
};

// Format and output the report to the console/log. No additional logic.
void PrintReport(const ReportDesc *rep);
void PrintStack(const ReportStack *stack);

}  // namespace __tsan

#endif  // TSAN_REPORT_H
