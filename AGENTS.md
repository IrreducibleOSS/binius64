## Monbijou

## Code Guidelines

- Add comments to the code which might not be obvious to a person/agent that is not familiar with the
  project.
- Add tests for new functionality, especially circuits. If the circuit has variable length inputs
  try to test all/most combinations. Pay attention to the edge cases (all zeroes, all ones).
- Test code with `cargo test --release`.
- Avoid introducing warnings in the code.
- Check that the code is properly formatted with `cargo fmt -- --check`.

## Circuit Design

- When designing a circuit consider the possibility that it might be easier to add the result as a
  witness, and verify that the result is correct.
- Try to minimize the circuit cost. Think of different possible arithmetizations.

## Monbijou Circuit Design Cheatsheet

Ultra‑short reference for building 64‑bit R1CS circuits compatible with the Monbijou proof system.

---

### 1 · Cost model

| Item                               | Symbol  | Relative cost |
| ---------------------------------- | ------- | ------------- |
| Bitwise **AND**                    | `nand`  | 1             |
| 64 × 64 → 128 **MUL**              | `nmul`  | μ≈200         |
| Commit **one 64‑bit word**         | `cword` | 0.2 ≈ 1⁄5 AND |
| `XOR`, single **shift**, constants | —       | 0             |

Total prover work (rough):

```
cost ≈ nand + μ·nmul + 0.2·ncommit
where   ncommit = ninout + nwitness
```

`cword` captures Merkle/digest bandwidth; five committed words cost about the same as one AND gate.

> **Rule 0**  Use **exactly one shift per operand index**—nested shifts like `(x>>1)<<32` are illegal.

---

### 2 · Operand syntax

```
(value_id, shift_op, s)   # shift_op∈{sll,srl,sra}, 0≤s≤63
```

Combine several such indices with **XOR** to build an *operand list*.
Each list element already encodes **one wire and one shift**; no further shifting is allowed.

---

### 2·1 · Primitive constraint shapes

**AND constraint**
Operand lists `I_x`, `I_y`, `I_z` each contain zero or more **shift‑indices** `(value_id, shift_op, s)`.
Let

```
X  =  ⊕  (shift(value_i, op_i, s_i) for i ∈ I_x)
Y  =  ⊕  (shift(value_j, op_j, s_j) for j ∈ I_y)
Z  =  ⊕  (shift(value_k, op_k, s_k) for k ∈ I_z)    # 64‑bit words
```

Constraint:

```
(X & Y) ^ Z  =  0          # 1 AND gate
```

Thus `Z` becomes the bitwise‑AND of the two XOR‑aggregated operands.

**MUL constraint**
Tuple `(I_a, I_b, I_hi, I_lo)` of four such lists:

```
A  =  ⊕ shift(... over I_a)
B  =  ⊕ shift(... over I_b)
HI =  ⊕ shift(... over I_hi)
LO =  ⊕ shift(... over I_lo)
```

Constraint:

```
A * B  =  (HI << 64) | LO   # full 128‑bit product equality, 1 MUL gate
```

Everything is modulo 2¹²⁸.
Cost: `μ` units per MUL; try to reuse words in `HI`, `LO` to suppress new witnesses.

### 3 · Common arithmetizations

| Intended op          | Constraints / recipe                                                | Gates (approx.) |
| -------------------- | ------------------------------------------------------------------- | --------------- |
| `z = x & y`          | single AND                                                          | 1               |
| `z = x ^ y`          | XOR only                                                            | 0               |
| `z = x \| y`         | `(x&y) ^ x ^ y = z`                                                 | 1               |
| `¬x`                 | `x ^ 0xFFFF…`                                                       | 0               |
| 64‑bit **add**       | carry‑out via XOR, 1 AND                                            | 1               |
| 64‑bit **sub**       | mirror of add                                                       | 1               |
| `x == y`             | `(x^y) & (all‑1) = 0`                                               | 1               |
| `z = sel ? a : b`    | `(sel & a) ^ (~sel & b)`                                            | 2               |
| `<` / `≤`            | diff + MSB extraction                                               | 1–2             |
| 256‑bit modular add  | four adds + cond. sub                                               | 5               |
| `z = c · x` (const)  | `k = popcount(c)−1` adds (≤ 63) **or** 1 MUL—shift‑add usually wins | ≤ 63            |
| 64‑bit **mul**       | tuple `(a,b,hi,lo)`                                                 | 1 MUL (μ)       |
| Modular mul / invert | compose MULs + adds                                                 | many MULs       |

---

### 4 · Checklist

*

That’s the essence—focus on shaving MULs, collapse logic into XOR+shift, and remember **one shift per index**.
