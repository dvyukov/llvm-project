//===-- tsan_defs.h ---------------------------------------------*- C++ -*-===//
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

#ifndef TSAN_DEFS_H
#define TSAN_DEFS_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "tsan_stat.h"
#include "ubsan/ubsan_platform.h"

#ifdef __SSE3__
// <emmintrin.h> transitively includes <stdlib.h>,
// and it's prohibited to include std headers into tsan runtime.
// So we do this dirty trick.
#define _MM_MALLOC_H_INCLUDED
#define __MM_MALLOC_H
#include <emmintrin.h>
typedef __m128i m128;
#define VECTOR_ALIGNED ALIGNED(16)
#else
#define VECTOR_ALIGNED
#endif

// Setup defaults for compile definitions.
#ifndef TSAN_NO_HISTORY
# define TSAN_NO_HISTORY 0
#endif

#ifndef TSAN_COLLECT_STATS
# define TSAN_COLLECT_STATS 0
#endif

#ifndef TSAN_CONTAINS_UBSAN
# if CAN_SANITIZE_UB && !SANITIZER_GO
#  define TSAN_CONTAINS_UBSAN 1
# else
#  define TSAN_CONTAINS_UBSAN 0
# endif
#endif

namespace __tsan {

enum class Sid : u8 {};
enum class Epoch : u16 {};

const Epoch kLastEpoch = static_cast<Epoch>(-1);
const int kByteBits = 8;
const uptr kMaxSid = 1 << (sizeof(Sid) * kByteBits);
const uptr kShadowStackSize = 64 * 1024;

// Count of shadow values in a shadow cell.
const uptr kShadowCnt = 4;

// That many user bytes are mapped onto a single shadow cell.
const uptr kShadowCell = 8;

// Size of a single shadow value (u32).
const uptr kShadowSize = 4;
typedef u32 RawShadow; //!!! strong typedef

// .rodata shadow marker, see MapRodata and ContainsSameAccessFast.
const RawShadow kShadowRodata = 1<<10;

// Shadow memory is kShadowMultiplier times larger than user memory.
const uptr kShadowMultiplier = kShadowSize * kShadowCnt / kShadowCell;

// That many user bytes are mapped onto a single meta shadow cell.
// Must be less or equal to minimal memory allocator alignment.
const uptr kMetaShadowCell = 8;

// Size of a single meta shadow value (u32).
const uptr kMetaShadowSize = 4;

#if TSAN_NO_HISTORY
const bool kCollectHistory = false;
#else
const bool kCollectHistory = true;
#endif

// The following "build consistency" machinery ensures that all source files
// are built in the same configuration. Inconsistent builds lead to
// hard to debug crashes.
#if SANITIZER_DEBUG
void build_consistency_debug();
#else
void build_consistency_release();
#endif

#if TSAN_COLLECT_STATS
void build_consistency_stats();
#else
void build_consistency_nostats();
#endif

static inline void USED build_consistency() {
#if SANITIZER_DEBUG
  build_consistency_debug();
#else
  build_consistency_release();
#endif
#if TSAN_COLLECT_STATS
  build_consistency_stats();
#else
  build_consistency_nostats();
#endif
}

template<typename T>
T min(T a, T b) {
  return a < b ? a : b;
}

template<typename T>
T max(T a, T b) {
  return a > b ? a : b;
}

template<typename T>
T RoundUp(T p, u64 align) {
  DCHECK_EQ(align & (align - 1), 0);
  return (T)(((u64)p + align - 1) & ~(align - 1));
}

template<typename T>
T RoundDown(T p, u64 align) {
  DCHECK_EQ(align & (align - 1), 0);
  return (T)((u64)p & ~(align - 1));
}

// Zeroizes high part, returns 'bits' lsb bits.
template<typename T>
T GetLsb(T v, int bits) {
  return (T)((u64)v & ((1ull << bits) - 1));
}

struct Processor;
struct ThreadState;
class ThreadContext;
struct TidSlot;
struct Context;
struct ReportStack;
class ReportDesc;
class RegionAlloc;

// Descriptor of user's memory block.
struct MBlock {
  u64  siz : 48;
  u64  tag : 16;
  StackID  stk;
  Tid  tid;
};
static_assert(sizeof(MBlock) == 16, "bad MBlock size");

enum ExternalTag : uptr {
  kExternalTagNone = 0,
  kExternalTagSwiftModifyingAccess = 1,
  kExternalTagFirstUserAvailable = 2,
  kExternalTagMax = 1024,
  // Don't set kExternalTagMax over 65,536, since MBlock only stores tags
  // as 16-bit values, see tsan_defs.h.
};

struct MD5Hash {
  u64 hash[2];
  bool operator==(const MD5Hash &other) const;
};

}  // namespace __tsan

#endif  // TSAN_DEFS_H
