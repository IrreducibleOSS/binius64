## Monbijou Circuit Design Cheatsheet

Ultra‑short reference for building 64‑bit R1CS circuits compatible with the Monbijou proof system.

---

## Structure

The goal of monbijou is given a constraint system and an input vector to provide a zero-knowledge proof that the input vector `z` satisfies that particular constraint system.

The constraint system is sort of a R1CS.

The constraint system defines the set of constraints and the length of input vector `z`. For a vector `z` it returns 1 if the vector satisfies the constraints of that particular constraint system, or 0 otherwise.

There are two types of constraints:

1. AND constraint,
2. MUL constraint.

The constraint system can declare a list of constants. Those constants will be added to the beginning of the input vector. Additionally, the constraint system declares the number of public values and private values in the input vector.

Thus, the total length of vector `z` is defined by the sum of the number of constants, the number of public values and the number of private values.

### Operand Syntax

Let's define shifted value index:

```
(value_id, shift_op, s)   # shift_op∈{sll,slr,sar}, 0≤s≤63
```

it means that the 64-bit value at the index `value_id` in the input list should be shifted by `s` bits according to shift\_op.

An operand is a XOR combination of the shift value indices. For example:

1. `v0 XOR (v1 srl 5)`. When no shift is specified, by convention, we assume `sll` with `s=0`.
2. `v55 XOR v100 XOR (v0 >> 1)` . `>>` is an alias for slr and is more preferable.
3. `(v2 sra 5) XOR (v100 sll 63) XOR v0`.
4. An operand with 0 terms is legal.

Note that it's illegal to have multiple shifts in an operand like follows:

`((v2 >> 5) sra 10)` 

### AND Constraint

AND(A, B, C) constraints: A & B ^ C = 0 where A, B and C are operands.

Examples:

| Operation                 | Operand A (X)                                            | Operand B (Y) | Operand C (Z)  | Meaning enforced          |
| ------------------------- | -------------------------------------------------------- | ------------- | -------------- | ------------------------- |
| **AND**                   | `v0`                                                     | `v1`          | `v2`           | `v2 = v0 & v1`            |
| **XOR**                   | `v0 ^ v1`                                                | `all‑1`       | `v2`           | `v2 = v0 ^ v1`            |
| **OR**                    | `v0`                                                     | `v1`          | `v0 ^ v1 ^ v2` | `v2 = v0 \| v1`           |
| **NOT**                   | `v0 ^ all‑1`                                             | `all‑1`       | `v1`           | `v1 = ¬v0`                |
| **equals**                | `v0 ^ v1`                                                | `all‑1`       | `0`            | asserts `v0 == v1`        |
| **rotate left by n bits** | `(v0 sll n) ^ (v0 srl (64‑n))` (note 64-n is a constant) | `all‑1`       | `v3`           | `v3 = rotate_left(v0, n)` |

Note that one constraint can only have A & B ^ C = 0 where A, B, C are  XOR-aggregated of shifted value indices. Let's examine the following example:

diff = a ^ ((a ^ b) & ((a − b) sra 63))

The reasons why this constraint is illegal:

1. Only input values (or shifted inputs) can be XORed. It's not possible to XOR the result of AND.
2. It's only possible to shift input values. It's not possible to shift the output of any operation.
3. Subtraction is not available, and must be represented as a list of XORs.

### MUL Constraint

MUL(A, B, HI, LO) constrains: A \* B = (HI << 64) | LO, where A, B, HI, LO are operands.

### Cost Model

| Item                             | Symbol  | Relative cost |
| -------------------------------- | ------- | ------------- |
| Bitwise **AND** constraint       | `num_and`  | 1             |
| 64 × 64 → 128 **MUL** constraint | `num_mul`  | μ≈8         |
| Commit **one 64‑bit word**       | `cword` | 0.2 ≈ 1⁄5 AND |

Total prover work (rough):

```
cost ≈ num_and + μ·num_mul + 0.2·ncommit
where   ncommit = ninout + nwitness
```

**Free inside a constraint** When assembling each operand of an AND or MUL gate you may XOR **any** number of *shifted* wires (or constants) at no extra charge. Shifts and literals are likewise free **inside** that gate.

**BUT** a stand‑alone XOR still burns **one AND**: e.g.

```
(x ^ y) & (all‑1)  ^ z  =  0      # implements  z = x ^ y
```

`cword` captures Merkle/digest bandwidth; five committed words cost about the same as one AND gate.

---

---

### Final Remarks

1. After the arithmetization is done it's useful to give the cost breakdown in terms of AND & MUL constraints. If any uncommon gates are used, provide their expansion in terms of AND and/or MUL constraints.
2. Consider that we are in the verification business and thus sometimes instead of calculating the result from scratch we could pass it through witness and in circuit verify that it was correct. Similarly, the prover can pass hints to simplify in-circuit logic.

### Formal Circuit Grammar (EBNF)

```ebnf
UINT       ::= DIGIT+
WORD       ::= "0x" HEX{1,16} | DIGIT+
ID         ::= "v" UINT
SHIFT_OP   ::= "sll" | "srl" | "sra"
INT6       ::= 0‥63

ShiftIndex ::= ID [ SHIFT_OP INT6 ]
Term       ::= ShiftIndex | WORD | "all-1"
Operand    ::= /* empty */ | Term { "^" Term }

AndConstraint ::= AND "(" Operand "," Operand "," Operand ")"
MulConstraint ::= MUL "(" Operand "," Operand "," Operand "," Operand ")"

ConstList      ::= "[" WORD { "," WORD } "]"
AndList        ::= "[" AndConstraint { "," AndConstraint } "]"
MulList        ::= "[" MulConstraint { "," MulConstraint } "]"

CircuitFile ::= {
    constants: ConstList,
    n_inout: UINT,
    n_witness: UINT,
    and_constraints: AndList,
    mul_constraints: MulList
}
```

---
