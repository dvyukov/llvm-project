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

class FastState {
 public:
  FastState() { Reset(); }

  void Reset() {
    part_.unused0_ = 0;
    part_.sid_ = kFreeSid;
    part_.epoch_ = static_cast<u16>(kEpochLast);
    part_.unused1_ = 0;
    part_.ignore_accesses_ = false;
  }

  void SetSid(Sid sid) { part_.sid_ = sid; }

  Sid sid() const { return part_.sid_; }

  Epoch epoch() const { return static_cast<Epoch>(part_.epoch_); }

  void SetEpoch(Epoch epoch) { part_.epoch_ = static_cast<u16>(epoch); }

  void SetIgnoreBit() { part_.ignore_accesses_ = 1; }
  void ClearIgnoreBit() { part_.ignore_accesses_ = 0; }
  bool GetIgnoreBit() const { return (s32)raw_ < 0; }

 private:
  friend class Shadow;
  struct Parts {
    u8 unused0_;
    Sid sid_;
    u16 epoch_ : kEpochBits;
    u16 unused1_ : 1;
    u16 ignore_accesses_ : 1;
  };
  union {
    Parts part_;
    u32 raw_;
  };
};

static_assert(sizeof(FastState) == kShadowSize, "bad FastState size");

constexpr RawShadow kShadowEmpty = static_cast<RawShadow>(0);
// .rodata shadow marker, see MapRodata and ContainsSameAccessFast.
constexpr RawShadow kShadowRodata = static_cast<RawShadow>(0x40000000);

class Shadow {
 public:
  Shadow(FastState state, u32 addr, u32 size, AccessType typ) {
    raw_ = state.raw_;
    SetAccess(addr, size, typ);
  }

  explicit Shadow(RawShadow x = kShadowEmpty) { raw_ = static_cast<u32>(x); }

  RawShadow raw() const { return static_cast<RawShadow>(raw_); }

  Sid sid() const { return part_.sid_; }

  void SetSid(Sid sid) { part_.sid_ = sid; }

  Epoch epoch() const { return static_cast<Epoch>(part_.epoch_); }

  void SetEpoch(Epoch epoch) {
    part_.epoch_ = static_cast<u16>(epoch);
    DCHECK_EQ(part_.epoch_, static_cast<u16>(epoch));
  }

  void SetAccess(u32 addr, u32 size, AccessType typ) {
    DCHECK_GT(size, 0);
    DCHECK_LE(size, 8);
    UNUSED Sid sid0 = part_.sid_;
    UNUSED u16 epoch0 = part_.epoch_;
    raw_ |= (!!(typ & kAccessAtomic) << 31) | (!!(typ & kAccessRead) << 30) |
            ((((1u << size) - 1) << (addr & 0x7)) & 0xff);
    DCHECK_EQ(addr0(), addr & 0x7);
    // Note: we don't check kAccessAtomic because is overlaps with
    // FastState::ignore_accesses_ and it may be set spuriously.
    DCHECK_EQ(IsRead(), !!(typ & kAccessRead));
    DCHECK_EQ(sid(), sid0);
    DCHECK_EQ(epoch(), epoch0);
  }

  bool IsAtomic() const { return part_.is_atomic_; }

  bool IsZero() const { return raw_ == 0; }

  static ALWAYS_INLINE bool SidsAreEqual(const Shadow s1, const Shadow s2) {
    return s1.part_.sid_ == s2.part_.sid_;
  }

  static ALWAYS_INLINE bool AddrSizeEqual(const Shadow cur, const Shadow old) {
    return cur.part_.access_ == old.part_.access_;
  }

  static ALWAYS_INLINE bool TwoRangesIntersect(Shadow cur, Shadow old) {
    return cur.part_.access_ & old.part_.access_;
  }

  ALWAYS_INLINE u8 access() const { return part_.access_; }
  u32 ALWAYS_INLINE addr0() const {
    DCHECK(part_.access_);
    return __builtin_ffs(part_.access_) - 1;
  }
  u32 ALWAYS_INLINE size() const {
    DCHECK(part_.access_);
    return part_.access_ == kFreeAccess ? kShadowCell
                                        : __builtin_popcount(part_.access_);
  }
  bool ALWAYS_INLINE IsWrite() const { return !IsRead(); }
  bool ALWAYS_INLINE IsRead() const { return part_.is_read_; }

  ALWAYS_INLINE
  bool IsBothReadsOrAtomic(bool kIsWrite, bool kIsAtomic) const {
    bool res = raw_ & ((u32(kIsAtomic) << 31) | (u32(kIsWrite ^ 1) << 30));
    DCHECK_EQ(res, (!IsWrite() && !kIsWrite) || (IsAtomic() && kIsAtomic));
    return res;
  }

  ALWAYS_INLINE bool IsRWWeakerOrEqual(Shadow cur, bool kIsWrite,
                                       bool kIsAtomic) const {
    DCHECK_EQ(raw_ & 0x3f, cur.raw_ & 0x3f);
    bool res = (raw_ & 0xc0000000) >=
               (((u32)kIsAtomic << 31) | ((kIsWrite ^ 1) << 30));
    DCHECK_EQ(res, (IsAtomic() > kIsAtomic) ||
                       (IsAtomic() == kIsAtomic && !IsWrite() >= !kIsWrite));
    return res;
  }

  ALWAYS_INLINE bool IsFree() const { return part_.access_ == kFreeAccess; }

  // The FreedMarker must not pass "the same access check" so that we don't
  // return from the race detection algorithm early.
  static RawShadow FreedMarker() {
    Shadow s;
    s.SetSid(kFreeSid);
    s.SetEpoch(kEpochLast);
    s.SetAccess(0, 8, kAccessWrite);
    return s.raw();
  }

  static RawShadow Freed(Sid sid, Epoch epoch) {
    Shadow s;
    s.SetSid(sid);
    s.SetEpoch(epoch);
    s.part_.access_ = kFreeAccess;
    return s.raw();
  }

 private:
  struct Parts {
    u8 access_;
    Sid sid_;
    u16 epoch_ : kEpochBits;
    u16 is_read_ : 1;
    u16 is_atomic_ : 1;
  };
  union {
    Parts part_;
    u32 raw_;
  };

  static constexpr u8 kFreeAccess = 0x81;
};

static_assert(sizeof(Shadow) == kShadowSize, "bad Shadow size");

}  // namespace __tsan

#endif
