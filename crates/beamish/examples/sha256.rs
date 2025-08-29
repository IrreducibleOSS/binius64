//! SHA-256 implementation using Beamish expression system

use binius_beamish::*;
use binius_beamish::types::U32;
use std::env;

/// SHA-256 initial hash values
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Single SHA-256 round
fn sha256_round(
    state: [Expr<U32>; 8],
    w: Expr<U32>,
    k: u32,
) -> [Expr<U32>; 8] {
    let [a, b, c, d, e, f, g, h] = state;
    
    // Σ1(e)
    let s1 = sha256_big_sigma1(&e);
    
    // Ch(e, f, g)
    let ch_val = ch(&e, &f, &g);
    
    // temp1 = h + Σ1(e) + Ch(e,f,g) + k + w
    let temp1 = add_many(&[
        h,
        s1,
        ch_val,
        constant(k as u64),
        w,
    ]);
    
    // Σ0(a)
    let s0 = sha256_big_sigma0(&a);
    
    // Maj(a, b, c)
    let maj_val = maj(&a, &b, &c);
    
    // temp2 = Σ0(a) + Maj(a,b,c)
    let temp2 = add(&s0, &maj_val);
    
    // Update state
    [
        add(&temp1, &temp2),  // new a
        a,                     // new b
        b,                     // new c
        c,                     // new d
        add(&d, &temp1),       // new e
        e,                     // new f
        f,                     // new g
        g,                     // new h
    ]
}

/// Message schedule expansion
fn message_schedule(block: [Expr<U32>; 16]) -> Vec<Expr<U32>> {
    let mut w = Vec::new();
    
    // First 16 words are the message block
    for i in 0..16 {
        w.push(block[i].clone());
    }
    
    // Expand to 64 words
    for i in 16..64 {
        let s0 = sha256_sigma0(&w[i - 15]);
        let s1 = sha256_sigma1(&w[i - 2]);
        let new_w = add_many(&[
            w[i - 16].clone(),
            s0,
            w[i - 7].clone(),
            s1,
        ]);
        w.push(new_w);
    }
    
    w
}

/// Process one 512-bit block
fn process_block(
    state: [Expr<U32>; 8],
    block: [Expr<U32>; 16],
    verbose: bool,
) -> [Expr<U32>; 8] {
    // Expand message schedule
    if verbose {
        println!("  Expanding message schedule...");
    }
    let w = message_schedule(block);
    
    // Initialize working variables
    let mut work = state.clone();
    
    // 64 rounds
    for i in 0..64 {
        if verbose && i % 8 == 0 {
            println!("  Processing rounds {}-{}...", i, std::cmp::min(i+7, 63));
        }
        work = sha256_round(work, w[i].clone(), K[i]);
    }
    
    // Add back to state
    [
        add(&state[0], &work[0]),
        add(&state[1], &work[1]),
        add(&state[2], &work[2]),
        add(&state[3], &work[3]),
        add(&state[4], &work[4]),
        add(&state[5], &work[5]),
        add(&state[6], &work[6]),
        add(&state[7], &work[7]),
    ]
}

fn main() {
    // Initialize logger with custom format
    env_logger::Builder::from_env(env_logger::Env::default())
        .format_timestamp(None)
        .format_module_path(false)
        .init();
    
    let args: Vec<String> = env::args().collect();
    let full_mode = args.len() > 1 && args[1] == "full";
    let verbose = args.contains(&String::from("--verbose")) || args.contains(&String::from("-v"));
    
    println!("SHA-256 Expression Demo");
    println!("=======================\n");
    
    if full_mode {
        println!("Mode: FULL (64 rounds - this will take time!)");
        println!("Tip: Run without 'full' argument for single-round demo");
        println!("     Add --verbose or -v to see progress\n");
    } else {
        println!("Mode: DEMO (single round only)");
        println!("Tip: Run with 'full' argument for complete SHA-256");
        println!("     Add --verbose or -v to see more details\n");
    }
    
    // Create initial state
    let state: [Expr<U32>; 8] = [
        constant(H_INIT[0] as u64),
        constant(H_INIT[1] as u64),
        constant(H_INIT[2] as u64),
        constant(H_INIT[3] as u64),
        constant(H_INIT[4] as u64),
        constant(H_INIT[5] as u64),
        constant(H_INIT[6] as u64),
        constant(H_INIT[7] as u64),
    ];
    
    let final_state = if full_mode {
        // Full SHA-256: Process one block
        println!("Processing full SHA-256 block (16 message words, 64 rounds)...");
        
        // Create a message block from witness values
        let block: [Expr<U32>; 16] = std::array::from_fn(|i| witness(i as u32));
        
        // Process the block
        let result = process_block(state, block, verbose);
        
        println!("Block processing complete!");
        result
    } else {
        // Demo: Just one round
        println!("Running single SHA-256 round...");
        
        // Create a single message word
        let w = witness::<U32>(0);
        
        // Run one round
        sha256_round(state, w, K[0])
    };
    
    // Skip expression display for full mode - it's too large to format efficiently
    if !full_mode {
        println!("\nExpression for output state[0] (new 'a'):");
        let expr_str = format!("{}", final_state[0]);
        if expr_str.len() > 200 {
            println!("  (truncated) {}...", &expr_str[..200]);
            println!("  Full expression length: {} characters", expr_str.len());
        } else {
            println!("  {}", expr_str);
        }
        println!();
    }
    
    // Generate constraints
    println!("Generating constraints...");
    let start = std::time::Instant::now();
    
    // Enable verbose mode for constraint generation
    if verbose {
        // Note: Setting env vars is unsafe, but we'll skip it for examples
        // The verbose flag is checked directly in the library
    }
    
    let constraints = to_constraints(&final_state[0]);
    
    let elapsed = start.elapsed();
    println!("Constraint generation took: {:.2?}", elapsed);
    println!("Total constraints: {}", constraints.len());
    println!();
    
    // Show constraint breakdown
    let mut and_count = 0;
    let mut mul_count = 0;
    for c in &constraints {
        match c {
            Constraint::And { .. } => and_count += 1,
            Constraint::Mul { .. } => mul_count += 1,
        }
    }
    
    println!("Constraint breakdown:");
    println!("  AND constraints: {}", and_count);
    println!("  MUL constraints: {}", mul_count);
    
    if full_mode {
        println!("\nNote: This represents the constraints for computing");
        println!("      the first output word of SHA-256 compression.");
        println!("      A complete SHA-256 would need constraints for");
        println!("      all 8 output words.");
    }
}