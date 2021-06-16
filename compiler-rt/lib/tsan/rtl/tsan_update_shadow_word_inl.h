//===-- tsan_update_shadow_word_inl.h ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// Body of the hottest inner loop.
// If we wrap this body into a function, compilers (both gcc and clang)
// produce sligtly less efficient code.
//===----------------------------------------------------------------------===//
do {
  RawShadow* sp = &shadow_mem[idx];
  old = LoadShadow(sp);
  if (LIKELY(old.IsZero())) {
    if (!stored)
      StoreShadow(sp, cur.raw());
    return;
  }
  if (LIKELY(!Shadow::TwoRangesIntersect(cur, old)))
    break;
  if (idx == 0 && UNLIKELY(old.IsFreed()))
    goto RACE;
  if (LIKELY(Shadow::SidsAreEqual(old, cur))) {
    if (LIKELY(Shadow::AddrSizeEqual(cur, old) &&
               old.IsRWWeakerOrEqual(cur, kAccessIsWrite, kIsAtomic))) {
      StoreShadow(sp, cur.raw());
      stored = true;
    }
    break;
  }
    if (LIKELY(old.IsBothReadsOrAtomic(kAccessIsWrite, kIsAtomic)))
      continue;
    if (HappensBefore(old, thr))
      break;
    goto RACE;
} while (0);
