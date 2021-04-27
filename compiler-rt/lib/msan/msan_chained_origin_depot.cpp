//===-- msan_chained_origin_depot.cpp -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// A storage for chained origins.
//===----------------------------------------------------------------------===//

#include "msan_chained_origin_depot.h"

#include "sanitizer_common/sanitizer_chained_origin_depot.h"

namespace __msan {

static ChainedOriginDepot chainedOriginDepot;

StackDepotStats *ChainedOriginDepotGetStats() {
  return chainedOriginDepot.GetStats();
}

bool ChainedOriginDepotPut(StackID here_id, StackID prev_id, StackID *new_id) {
  return chainedOriginDepot.Put(here_id, prev_id, new_id);
}

StackID ChainedOriginDepotGet(StackID id, StackID *other) {
  return chainedOriginDepot.Get(id, other);
}

void ChainedOriginDepotLockAll() {
  chainedOriginDepot.LockAll();
}

void ChainedOriginDepotUnlockAll() {
  chainedOriginDepot.UnlockAll();
}

} // namespace __msan
