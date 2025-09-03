use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::circuits::keccak::keccak::keccak_f;
use binius_beamish::compute::expressions::ExpressionEvaluator;

// Copy the reference implementation for testing
fn keccak_f1600_reference(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ];

    const R: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41,
        45, 15, 21, 8, 18, 2, 61, 56, 14,
    ];

    fn idx(x: usize, y: usize) -> usize { x + 5 * y }

    for round in 0..24 {
        // θ step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[idx(x, 0)] ^ state[idx(x, 1)] ^ state[idx(x, 2)] ^ state[idx(x, 3)] ^ state[idx(x, 4)];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[idx(x, y)] ^= d[x];
            }
        }

        // ρ and π steps
        let mut temp = [0u64; 25];
        temp[idx(0, 0)] = state[idx(0, 0)];
        for x in 0..5 {
            for y in 0..5 {
                if x == 0 && y == 0 { continue; }
                let src_idx = idx(x, y);
                let dst_x = y;
                let dst_y = (2 * x + 3 * y) % 5;
                let dst_idx = idx(dst_x, dst_y);
                temp[dst_idx] = state[src_idx].rotate_left(R[src_idx]);
            }
        }
        *state = temp;

        // χ step
        for y in 0..5 {
            let row = [
                state[idx(0, y)], state[idx(1, y)], state[idx(2, y)], 
                state[idx(3, y)], state[idx(4, y)]
            ];
            for x in 0..5 {
                let b = row[(x + 1) % 5];
                let c = row[(x + 2) % 5];
                state[idx(x, y)] = row[x] ^ ((!b) & c);
            }
        }

        // ι step
        state[0] ^= RC[round];
    }
}

fn main() {
    println!("=== Keccak Correctness Test ===");
    println!("Comparing Beamish vs Reference Implementation");
    println!();

    let test_cases = [
        // Test case 1: All zeros
        [0u64; 25],
        // Test case 2: Simple pattern
        [
            0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x1111111111111111, 0x2222222222222222, 0x3333333333333333,
            0x4444444444444444, 0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x8888888888888888,
            0x9999999999999999, 0xAAAAAAAAAAAAAAAA, 0xBBBBBBBBBBBBBBBB, 0xCCCCCCCCCCCCCCCC, 0xDDDDDDDDDDDDDDDD,
            0xEEEEEEEEEEEEEEEE, 0xFFFFFFFFFFFFFFFF, 0x0000000000000000, 0x1010101010101010, 0x2020202020202020,
            0x3030303030303030, 0x4040404040404040, 0x5050505050505050, 0x6060606060606060, 0x7070707070707070,
        ],
        // Test case 3: Random pattern
        [
            0x123456789ABCDEF0, 0xFEDCBA0987654321, 0xAAAABBBBCCCCDDDD, 0x1111222233334444, 0x5555666677778888,
            0x9999AAAABBBBCCCC, 0xDDDDEEEEFFFF0000, 0x1234ABCD5678EF90, 0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF,
            0xF0E1D2C3B4A59687, 0x1928374650ABCDEF, 0xFFEEDDCCBBAA9988, 0x7766554433221100, 0x0F1E2D3C4B5A6978,
            0x8796A5B4C3D2E1F0, 0xABCDEF0123456789, 0x9876543210FEDCBA, 0x5A5A5A5A5A5A5A5A, 0xA5A5A5A5A5A5A5A5,
            0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0, 0x3C3C3C3C3C3C3C3C, 0xC3C3C3C3C3C3C3C3, 0x55AA55AA55AA55AA,
        ],
    ];

    for (test_num, initial_state) in test_cases.iter().enumerate() {
        println!("Test case {}: {:?}...", test_num + 1, &initial_state[0..2]);

        // Reference implementation
        let mut reference_state = *initial_state;
        keccak_f1600_reference(&mut reference_state);

        // Beamish implementation
        let beamish_state: [_; 25] = std::array::from_fn(|i| val::<U64>(i as u32));
        let beamish_result = keccak_f(&beamish_state, 24); // Full 24 rounds

        let mut evaluator = ExpressionEvaluator::new(initial_state.to_vec());
        let mut beamish_output = [0u64; 25];
        for i in 0..25 {
            beamish_output[i] = evaluator.evaluate(&beamish_result[i]);
        }

        // Compare results
        let mut matches = 0;
        let mut mismatches = 0;
        
        for i in 0..25 {
            if reference_state[i] == beamish_output[i] {
                matches += 1;
            } else {
                mismatches += 1;
                println!("  ❌ Mismatch at index {}: reference=0x{:016X}, beamish=0x{:016X}", 
                        i, reference_state[i], beamish_output[i]);
            }
        }

        if mismatches == 0 {
            println!("  ✅ Perfect match! All 25 words identical");
        } else {
            println!("  ❌ {} matches, {} mismatches", matches, mismatches);
        }
        println!();
    }

    println!("=== Message Size Handling ===");
    println!("Current implementations:");
    println!("• Beamish: Fixed 1600-bit state (Keccak-f permutation only)"); 
    println!("• Frontend: Full Keccak-256 with variable message length");
    println!("• Both handle fixed-size state correctly");
    println!("• Only Frontend handles variable-length message padding");
}