use crate::{
    circuit::{CircuitBuilder, Wire},
    constraint_system::Witness,
    word::Word,
};

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// 512-bit state of SHA-256.
#[derive(Clone)]
pub struct State(pub [Wire; 8]);

impl State {
    pub fn new(wires: [Wire; 8]) -> Self {
        State(wires)
    }

    pub fn public(builder: &mut CircuitBuilder) -> Self {
        State(std::array::from_fn(|i| builder.add_public()))
    }

    pub fn private(builder: &mut CircuitBuilder) -> Self {
        State(std::array::from_fn(|i| builder.add_private()))
    }

    pub fn iv(builder: &mut CircuitBuilder) -> Self {
        State(std::array::from_fn(|i| {
            builder.add_constant(Word(IV[i] as u64))
        }))
    }
}

/// SHA-256 compress function.
pub struct Compress {
    pub state_in: State,
    pub state_out: State,
    pub m: [Wire; 16],
}

impl Compress {
    pub fn new(builder: &mut CircuitBuilder, state_in: State, m: [Wire; 16]) -> Self {
        // ---- message-schedule ----
        // W[0..15] = block_words & M32
        // for t = 16 .. 63:
        //     s0   = σ0(W[t-15])
        //     s1   = σ1(W[t-2])
        //     (p, _)  = Add32(W[t-16], s0)
        //     (q, _)  = Add32(p, W[t-7])
        //     (W[t],_) = Add32(q, s1)
        let m32 = builder.add_constant(Word::MASK_32);
        let m_masked: [Wire; 16] = std::array::from_fn(|i| builder.band(m[i], m32));

        let mut w: Vec<Wire> = Vec::with_capacity(64);

        // W[0..15] = block_words & M32
        for t in 0..16 {
            w.push(m_masked[t]);
        }

        // W[16..63] computed from previous W values
        for t in 16..64 {
            let s0 = small_sigma_0(builder, w[t - 15]);
            let s1 = small_sigma_1(builder, w[t - 2]);
            let p = builder.iadd_32(w[t - 16], s0);
            let q = builder.iadd_32(p, w[t - 7]);
            w.push(builder.iadd_32(q, s1));
        }

        let w: &[Wire; 64] = (&*w).try_into().unwrap();
        let mut state = state_in.clone();
        for t in 0..64 {
            state = round(builder, t, state, w);
        }

        // Add the compressed chunk to the current hash value
        let state_out = State([
            builder.iadd_32(state_in.0[0], state.0[0]),
            builder.iadd_32(state_in.0[1], state.0[1]),
            builder.iadd_32(state_in.0[2], state.0[2]),
            builder.iadd_32(state_in.0[3], state.0[3]),
            builder.iadd_32(state_in.0[4], state.0[4]),
            builder.iadd_32(state_in.0[5], state.0[5]),
            builder.iadd_32(state_in.0[6], state.0[6]),
            builder.iadd_32(state_in.0[7], state.0[7]),
        ]);

        Compress {
            state_in,
            state_out,
            m,
        }
    }

    pub fn populate_m(&self, witness: &mut Witness, m: [u8; 64]) {
        debug_assert_eq!(self.m.len(), 16);

        for i in 0..16 {
            let j = i * 4;
            // Assemble a 32-bit big-endian word and widen to 64 bits.
            let limb = ((m[j] as u64) << 24)
                | ((m[j + 1] as u64) << 16)
                | ((m[j + 2] as u64) << 8)
                | (m[j + 3] as u64);

            // Write it to the witness.  Word is a thin wrapper around u64.
            witness.set(self.m[i].0, Word(limb));
        }
    }
}

fn round(builder: &mut CircuitBuilder, round: usize, state: State, w: &[Wire; 64]) -> State {
    let State([a, b, c, d, e, f, g, h]) = state;

    let big_sigma_e = big_sigma_1(builder, e);
    let ch_efg = ch(builder, e, f, g);
    let t1a = builder.iadd_32(h, big_sigma_e);
    let t1b = builder.iadd_32(t1a, ch_efg);
    let rc = builder.add_constant(Word(K[round] as u64));
    let t1c = builder.iadd_32(t1b, rc);
    let t1 = builder.iadd_32(t1c, w[round]);

    let big_sigma_a = big_sigma_0(builder, a);
    let maj_abc = maj(builder, a, b, c);
    let t2 = builder.iadd_32(big_sigma_a, maj_abc);

    let h = g;
    let g = f;
    let f = e;
    let e = builder.iadd_32(d, t1);
    let d = c;
    let c = b;
    let b = a;
    let a = builder.iadd_32(t1, t2);

    State([a, b, c, d, e, f, g, h])
}

/// Ch(e,f,g)   = XOR( AND(e,f), AND( NOT(e), g ) )
fn ch(builder: &mut CircuitBuilder, e: Wire, f: Wire, g: Wire) -> Wire {
    let a = builder.band(e, f);
    let a1 = builder.bnot(e);
    let b1 = builder.band(a1, g);
    builder.bxor(a, b1)
}

/// Maj(a,b,c)  = XOR( XOR( AND(a,b), AND(a,c) ), AND(b,c) )
fn maj(builder: &mut CircuitBuilder, a: Wire, b: Wire, c: Wire) -> Wire {
    let a1 = builder.band(a, b);
    let a2 = builder.band(a, c);
    let a3 = builder.bxor(a1, a2);
    let a4 = builder.band(b, c);
    builder.bxor(a3, a4)
}

/// Σ0(a)       = XOR( XOR( ROTR(a,  2), ROTR(a, 13) ), ROTR(a, 22) )
fn big_sigma_0(b: &mut CircuitBuilder, a: Wire) -> Wire {
    let r1 = b.rotr_32(a, 2);
    let r2 = b.rotr_32(a, 13);
    let r3 = b.rotr_32(a, 22);
    let x1 = b.bxor(r1, r2);
    b.bxor(x1, r3)
}

/// Σ1(e)       = XOR( XOR( ROTR(e,  6), ROTR(e, 11) ), ROTR(e, 25) )
fn big_sigma_1(b: &mut CircuitBuilder, e: Wire) -> Wire {
    let r1 = b.rotr_32(e, 6);
    let r2 = b.rotr_32(e, 11);
    let r3 = b.rotr_32(e, 25);
    let x1 = b.bxor(r1, r2);
    b.bxor(x1, r3)
}

/// σ0(x)       = XOR( XOR( ROTR(x,  7), ROTR(x, 18) ), SHR(x,  3) )
fn small_sigma_0(b: &mut CircuitBuilder, x: Wire) -> Wire {
    let r1 = b.rotr_32(x, 7);
    let r2 = b.rotr_32(x, 18);
    let s1 = b.shr_32(x, 3);
    let x1 = b.bxor(r1, r2);
    b.bxor(x1, s1)
}

/// σ1(x)       = XOR( XOR( ROTR(x, 17), ROTR(x, 19) ), SHR(x, 10) )
fn small_sigma_1(b: &mut CircuitBuilder, x: Wire) -> Wire {
    let r1 = b.rotr_32(x, 17);
    let r2 = b.rotr_32(x, 19);
    let s1 = b.shr_32(x, 10);
    let x1 = b.bxor(r1, r2);
    b.bxor(x1, s1)
}
