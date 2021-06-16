//===-- tsan_shadow.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef TSAN_SHADOW_H
#define TSAN_SHADOW_H

#include "tsan_defs.h"

namespace __tsan {

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
    return static_cast<Epoch>(epoch_);
  }

  void SetEpoch(Epoch epoch) {
    epoch_ = static_cast<u16>(epoch);
    DCHECK_EQ(epoch_, static_cast<u16>(epoch));
  }

  void SetAccess(u32 addr, u32 size, bool isRead, bool isAtomic, bool isFreed) {
    // DCHECK_EQ(raw_ & 0xff, 0);
    DCHECK_GT(size, 0);
    DCHECK_LE(size, 8);
    Sid sid0 = sid_;
    (void)sid0;
    u16 epoch0 = epoch_;
    (void)epoch0;
    raw_ |= (isAtomic << 31) | (isRead << 30) | (isFreed << 29) |
            ((((1u << size) - 1) << (addr & 0x7)) & 0xff);
    DCHECK_EQ(addr0(), addr & 0x7);
    DCHECK_EQ(IsAtomic(), isAtomic);
    DCHECK_EQ(IsRead(), isRead);
    DCHECK_EQ(IsFreed(), isFreed);
    DCHECK_EQ(sid(), sid0);
    DCHECK_EQ(epoch(), epoch0);
  }

  bool IsAtomic() const {
    return is_atomic_;
  }

  bool IsZero() const {
    return raw_ == 0;
  }

  static inline bool SidsAreEqual(const Shadow s1, const Shadow s2) {
    //!!! consider using ^&
    return s1.sid_ == s2.sid_;
  }

  static ALWAYS_INLINE bool AddrSizeEqual(const Shadow cur, const Shadow old) {
    return cur.access_ == old.access_;
  }

  static ALWAYS_INLINE bool AddrSizeEqualNotFreed(const Shadow cur,
                                                  const Shadow old) {
    DCHECK(!cur.IsFreed());
    bool res = ((cur.raw_ ^ old.raw_) & 0x200000ff) == 0;
    DCHECK_EQ(res,
              cur.access_ == old.access_ && cur.is_freed_ == old.is_freed_);
    return res;
  }

  static ALWAYS_INLINE bool TwoRangesIntersect(Shadow cur, Shadow old) {
    return cur.access_ & old.access_;
  }

  ALWAYS_INLINE u32 access() const {
    return access_;
  }
  u32 ALWAYS_INLINE addr0() const {
    DCHECK(access_);
    return __builtin_ffs(access_) - 1;
  }
  u32 ALWAYS_INLINE size() const {
    DCHECK(access_);
    return __builtin_popcount(access_);
  }
  bool ALWAYS_INLINE IsWrite() const {
    return !IsRead();
  }
  bool ALWAYS_INLINE IsRead() const {
    return is_read_;
  }

  bool IsFreed() const {
    return is_freed_;
  }

  ALWAYS_INLINE
  bool IsBothReadsOrAtomic(bool kIsWrite, bool kIsAtomic) const {
    bool res = raw_ & ((u32(kIsAtomic) << 31) | (u32(kIsWrite ^ 1) << 30));
    DCHECK_EQ(res, (!IsWrite() && !kIsWrite) || (IsAtomic() && kIsAtomic));
    return res;
  }

  ALWAYS_INLINE
  static bool SidsAreEqualOrBothReadsOrAtomic(Shadow cur, Shadow old,
                                              bool kIsWrite, bool kIsAtomic) {
    //!!! if we move bits to the low byte, we could do:
    // (((cur.raw_ ^ old.raw_) & 0xff00) | ((cur.raw_ & old.raw_) 0x3)) - 1 <=
    // 2;
#if 0
    //bool res = (((cur.raw_ ^ old.raw_) & 0xff00) | (old.raw_ & ((kIsWrite ^ 1) | (kIsAtomic << 1)))) - 1 <= 2;
#else
    bool res =
        (cur.sid_ == old.sid_) ||
        (old.raw_ & ((u32(kIsAtomic) << 31) | (u32(kIsWrite ^ 1) << 30)));
#endif
    DCHECK_EQ(res, SidsAreEqual(cur, old) ||
                       old.IsBothReadsOrAtomic(kIsWrite, kIsAtomic));
    return res;
  }

  bool ALWAYS_INLINE IsRWWeakerOrEqual(Shadow cur, bool kIsWrite,
                                       bool kIsAtomic) const {
    DCHECK_EQ(raw_ & 0x3f, cur.raw_ & 0x3f);
    bool res = (raw_ & 0xc0000000) >=
               (((u32)kIsAtomic << 31) | ((kIsWrite ^ 1) << 30));
    DCHECK_EQ(res, (IsAtomic() > kIsAtomic) ||
                       (IsAtomic() == kIsAtomic && !IsWrite() >= !kIsWrite));
    return res;
  }

  // .rodata shadow marker, see MapRodata and ContainsSameAccessFast.
  static constexpr RawShadow kShadowRodata = 0x40000001;

private:
  union {
    struct {
      u8 access_;
      Sid sid_;
      u16 epoch_ : 13;
      u16 is_freed_ : 1;
      u16 is_read_ : 1;
      u16 is_atomic_ : 1;
    };
    RawShadow raw_;
  };
};

static_assert(sizeof(Shadow) == kShadowSize, "bad Shadow size");

} // namespace __tsan

#endif
