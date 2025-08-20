import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

-- Interpret w as an unsigned integer
notation "[" w "]_u" => (BitVec.toNat w : Int)
-- Interpret w as a signed integer (two's complement)
notation "[" w "]_s" => BitVec.toInt w

@[simp]
def BitVec.msbI (w: BitVec n) := if w.msb then 1 else 0

@[simp]
theorem signed_unsigned_relationship
  (w : BitVec 64) :
  [w]_s
    = [w]_u - 2^64 * w.msbI := by
    by_cases h : w.msb <;> simp [BitVec.toInt_eq_msb_cond, h]

@[simp]
lemma signed_unsigned_multiplication_1
  (a b : BitVec 64) :
  [a]_s * [b]_s
    = ([a]_u - 2^64 * a.msbI) * ([b]_u - 2^64 * b.msbI) :=
    by simp

@[simp]
lemma signed_unsigned_multiplication_2
  (a b : BitVec 64) :
  ([a]_u - 2^64 * a.msbI) * ([b]_u - 2^64 * b.msbI)
    = ([a]_u * [b]_u) - [a]_u * 2^64 * b.msbI - [b]_u * 2^64 * a.msbI + 2^128 * a.msbI * b.msbI :=
    by grind

@[simp]
lemma signed_unsigned_multiplication
  (a b: BitVec 64) :
  [a]_s * [b]_s
    = ([a]_u * [b]_u) - [a]_u * 2^64 * b.msbI - [b]_u * 2^64 * a.msbI + 2^128 * a.msbI * b.msbI := by
    rw [signed_unsigned_multiplication_1]
    rw [signed_unsigned_multiplication_2]

@[simp]
theorem signed_unsigned_multiplication_mod
  (a b: BitVec 64) :
  ([a]_s * [b]_s : ZMod (2^128))
    = ([a]_u * [b]_u) - [a]_u * 2^64 * b.msbI - [b]_u * 2^64 * a.msbI := by
  simp
  grind

@[simp]
lemma split64_zmod (x : Int) :
  ∃ hi lo : BitVec 64,
    (x : ZMod (2^128))
      = [hi]_u * 2^64 + [lo]_u := by
  let n := (x : ZMod (2^128)).val
  let lo_nat := n % (2^64)
  let hi_nat := n / (2^64)
  use BitVec.ofNat 64 hi_nat
  use BitVec.ofNat 64 lo_nat

  simp only [BitVec.toNat_ofNat]
  have h_lo_bound : lo_nat < 2^64 := Nat.mod_lt n (by decide : 0 < 2^64)
  have h_hi_bound : hi_nat < 2^64 := by
    have : n < 2^128 := ZMod.val_lt _
    have : n / 2^64 < 2^128 / 2^64 := by grind
    grind

  simp only [Nat.mod_eq_of_lt h_hi_bound, Nat.mod_eq_of_lt h_lo_bound]
  have split_eq : n = hi_nat * 2^64 + lo_nat := by grind

  have x_eq : (x : ZMod (2^128)) = (n : ZMod (2^128)) := by
    have cast_val : (ZMod.val (x : ZMod (2^128)) : ZMod (2^128)) = x := by simp
    grind

  rw [x_eq, split_eq]
  simp
  rfl

@[simp]
theorem unsigned_mul_split_zmod (a b : BitVec 64) :
  ∃ hiU loU : BitVec 64,
    (([a]_u * [b]_u : Int) : ZMod (2^128))
      = [hiU]_u * 2^64
        + [loU]_u := by
  obtain ⟨hi, lo, h_split⟩ := split64_zmod ([a]_u * [b]_u)
  use hi, lo

theorem signed_hi_lo_from_unsigned
  (a b hiU loU : BitVec 64)
  (hU : (([a]_u * [b]_u : Int) : ZMod (2^128))
          = [hiU]_u * 2^64 + [loU]_u) :
  ∃ hiS loS : BitVec 64,
    (([a]_s * [b]_s : Int) : ZMod (2^128))
      = [hiS]_u * 2^64 + [loS]_u ∧
    loS = loU ∧
    [hiS]_u
      = (([hiU]_u : Int) - [a]_u * b.msbI - [b]_u * a.msbI).emod (2^64) := by
  let correction := [a]_u * b.msbI + [b]_u * a.msbI
  let hiS_val := ([hiU]_u : Int) - correction
  let hiS := BitVec.ofNat 64 (hiS_val.emod (2^64)).toNat
  use hiS, loU
  constructor
  · sorry
  constructor
  · rfl
  · sorry
