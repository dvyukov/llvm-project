//===-- tsan_clock.cpp ----------------------------------------------------===//
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
#include "tsan_clock.h"
#include "tsan_rtl.h"
#include "sanitizer_common/sanitizer_placement_new.h"

namespace __tsan {

#if defined(__SSE3__)
const uptr kClockSize128 = kMaxSid * sizeof(Epoch) / sizeof(__m128i);
#endif

VectorClock::VectorClock() {
  Reset();
}

void VectorClock::Reset() {
#if defined(__SSE3__)
  __m128i z = _mm_setzero_si128();
  __m128i* dst = reinterpret_cast<__m128i*>(clk_);
  for (uptr i = 0; i < kClockSize128; i++)
    _mm_store_si128(&dst[i], z);
    //_mm_max_epu16
    //__m128i _mm_load_si128 (__m128i const* mem_addr)
    // void _mm_store_si128 (__m128i* mem_addr, __m128i a)
#else
  for (uptr i = 0; i < kMaxSid; i++)
    clk_[i] = kEpochZero;
#endif
}

void VectorClock::Acquire(const VectorClock* src) {
  if (!src)
    return;
  for (uptr i = 0; i < kMaxSid; i++)
    clk_[i] = max(clk_[i], src->clk_[i]);
}

VectorClock* AllocClock(VectorClock** dstp) {
  if (!*dstp)
    *dstp = New<VectorClock>();
  return *dstp;
}

void VectorClock::Release(VectorClock** dstp) const {
  VectorClock* dst = AllocClock(dstp);
  for (uptr i = 0; i < kMaxSid; i++)
    dst->clk_[i] = max(dst->clk_[i], clk_[i]);
}

void VectorClock::ReleaseStore(VectorClock** dstp) const {
  VectorClock* dst = AllocClock(dstp);
  *dst = *this;
}

void VectorClock::operator=(const VectorClock& other) {
  for (uptr i = 0; i < kMaxSid; i++)
    clk_[i] = other.clk_[i];
}

void VectorClock::ReleaseStoreAcquire(VectorClock** dstp) {
  VectorClock* dst = AllocClock(dstp);
  for (uptr i = 0; i < kMaxSid; i++) {
    Epoch tmp = dst->clk_[i];
    dst->clk_[i] = clk_[i];
    clk_[i] = max(clk_[i], tmp);
  }
}

void VectorClock::ReleaseAcquire(VectorClock** dstp) {
  VectorClock* dst = AllocClock(dstp);
  for (uptr i = 0; i < kMaxSid; i++) {
    dst->clk_[i] = max(dst->clk_[i], clk_[i]);
    clk_[i] = dst->clk_[i];
  }
}

}  // namespace __tsan
