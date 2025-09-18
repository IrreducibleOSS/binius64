# Custom LLVM Pipeline Investigation

## Artifact generation

Use our CLI with the new environment variables to capture both the raw and the
post-pass IR, as well as the final assembly. Example (single Keccak permutation
for small output):

```bash
MONBIJOU_LLVM_EVAL=1 \
MONBIJOU_LLVM_DUMP_IR_RAW=target/keccak_raw.ll \
MONBIJOU_LLVM_DUMP_IR=target/keccak_after.ll \
MONBIJOU_LLVM_DUMP_ASM=target/keccak_after.s \
cargo run --release --example keccak -- -n 1
```

`keccak_raw.ll` is the immediate output of our lowering (no passes). When
`MONBIJOU_LLVM_OPT=custom`, `keccak_after.ll` captures the IR after whatever
pass list we configure in `run_custom_pipeline`. The assembly file mirrors that
same choice.

## Opt/llc experimentation

Work on `target/keccak_raw.ll` directly to test pass sequences without
rebuilding the binary:

```bash
PASSES="instcombine,reassociate,gvn,simplifycfg,adce"
/USR/LOCAL/OPT/LLVM/BIN/opt -passes="$PASSES" target/keccak_raw.ll -S -o /tmp/out.ll
/USR/LOCAL/OPT/LLVM/BIN/llc /tmp/out.ll -O0 -filetype=asm -o /tmp/out.s
```

Record:
- pass string
- `wc -l /tmp/out.s`
- `grep -c '\tstr' /tmp/out.s`
- stack allocation size if we decide to parse it later

We can optionally plug the same pass string into the code (`run_custom_pipeline`
uses the `module.run_passes` API) for a quick real run once the triangle looks
promising, but the initial sweep can focus on assembly/code size.

## Candidate passes to evaluate

Only scalar and general-purpose passes are likely to matter for our IR (no
loops, no allocas, straight-line bit/arith operations). Keep the list tight:

- Canonicalization / SSA: `sroa`, `mem2reg`
- Simplification: `instcombine`, `aggressive-instcombine`, `reassociate`,
  `simplifycfg`, `constprop`, `ipsccp`, `correlated-propagation`, `early-cse`,
  `gvn`, `newgvn`
- Cleanup: `adce`, `dce`, `bdce`, `dse`, `memcpyopt`
- CSE variants: `gvn-hoist`, `gvn-sink`
- Stretch passes (probably no effect but worth confirming): `slp-vectorizer`,
  `loop-vectorize`, `vector-combine`, etc.

Avoid target-specific or loop-specific passes unless we later discover we need
them; there are no allocas or loops in our starting IR, so many aren’t
applicable.

## Experiment matrix

1. Run each candidate pass individually to see if it materially changes the
   assembly (lines, store count, frame size).
2. Build up cumulative pipelines starting from the current best (`instcombine,
   reassociate, gvn, simplifycfg, adce`) and add passes one at a time.
3. Try a few broader combinations such as “default<O1>”, “default<O2>” for
   comparison.

The raw IR/assembly dumps make it easy to iterate purely with `opt`/`llc`. Once
we’ve collected the data, we can pick the best-performing sequence to hard-code
(one-line change in `run_custom_pipeline`) and re-run the example once for
sanity.
(paragraph appended…)
