//===-- tsan_rtl_thread.cpp -----------------------------------------------===//
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
do {
    StatInc(thr, StatShadowProcessed);
    RawShadow* sp = &shadow_mem[idx];
    old = LoadShadow(sp);
    if (LIKELY(old.IsZero())) {
      StatInc(thr, StatShadowZero);
      if (store_word)
        StoreShadow(sp, store_word);
      return;
    }
    // is the memory access equal to the previous?
    if (LIKELY(Shadow::Addr0AndSizeAreEqual(cur, old))) {
      StatInc(thr, StatShadowSameSize);
      //!!! include this into Addr0AndSizeAreEqual check
      if (idx == 0 && old.IsFreed())
        goto RACE;
      // same thread?
      if (LIKELY(Shadow::SidsAreEqual(old, cur))) {
        StatInc(thr, StatShadowSameThread);
        if (LIKELY(old.IsRWWeakerOrEqual(kAccessIsWrite, kIsAtomic)))
          StoreAndZero(sp, &store_word);
        break;
      }
      StatInc(thr, StatShadowAnotherThread);
      if (HappensBefore(old, thr)) {
        if (old.IsRWWeakerOrEqual(kAccessIsWrite, kIsAtomic))
          StoreAndZero(sp, &store_word);
        break;
      }
      if (LIKELY(old.IsBothReadsOrAtomic(kAccessIsWrite, kIsAtomic)))
        break;
      goto RACE;
    }
    // Do the memory access intersect?
    if (Shadow::TwoRangesIntersect(old, cur)) {
      StatInc(thr, StatShadowIntersect);
      if (idx == 0 && UNLIKELY(old.IsFreed()))
        goto RACE;
      if (Shadow::SidsAreEqual(old, cur)) {
        StatInc(thr, StatShadowSameThread);
        break;
      }
      StatInc(thr, StatShadowAnotherThread);
      if (old.IsBothReadsOrAtomic(kAccessIsWrite, kIsAtomic))
        break;
      if (LIKELY(HappensBefore(old, thr)))
        break;
      goto RACE;
    }
    // The accesses do not intersect.
    StatInc(thr, StatShadowNotIntersect);
} while (0);
