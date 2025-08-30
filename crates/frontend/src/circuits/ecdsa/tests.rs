use binius_core::word::Word;
use hex_literal::hex;

use super::scalar_mul::scalar_mul_naive;
use crate::{
	circuits::{
		bignum::{BigUint, assert_eq},
		ecdsa::{bitcoin_verify, ecrecover},
		secp256k1::{Secp256k1, Secp256k1Affine},
	},
	compiler::CircuitBuilder,
};

#[test]
pub fn test_bitcoin_ecdsa_test_vector() {
	let builder = CircuitBuilder::new();

	let [pkx, pky, z, r, s] = [
		hex!("3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF"),
		hex!("E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A"),
		hex!("3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F"),
		hex!("A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089"),
		hex!("BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB"),
	]
	.map(|bytes| {
		let native = num_bigint::BigUint::from_bytes_be(&bytes);
		BigUint::new_constant(&builder, &native)
	});

	let is_point_at_infinity = builder.add_constant(Word::ZERO);
	let pk = Secp256k1Affine {
		x: pkx,
		y: pky,
		is_point_at_infinity,
	};

	let signature_valid = bitcoin_verify(&builder, pk, &z, &r, &s);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();
	cs.populate_wire_witness(&mut w).unwrap();

	assert_eq!(w[signature_valid] >> 63, Word::ONE);
}

#[test]
pub fn test_ecdsa_recover_test_vector() {
	let builder = CircuitBuilder::new();

	let [pkx, pky, z, r, s] = [
		hex!("3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF"),
		hex!("E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A"),
		hex!("3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F"),
		hex!("A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089"),
		hex!("BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB"),
	]
	.map(|bytes| {
		let native = num_bigint::BigUint::from_bytes_be(&bytes);
		BigUint::new_constant(&builder, &native)
	});

	let recid_odd = builder.add_constant(Word::ALL_ONE);
	let pk = ecrecover(&builder, &z, &r, &s, recid_odd);

	assert_eq(&builder, "pkx", &pk.x, &pkx);
	assert_eq(&builder, "pky", &pk.y, &pky);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();
	assert!(cs.populate_wire_witness(&mut w).is_ok());
}

#[test]
pub fn test_scalar_mul_naive() {
	let builder = CircuitBuilder::new();
	let curve = Secp256k1::new(&builder);

	// Test vector: scalar * G = known point
	// Using a small scalar for initial testing: 3
	// 3 * G should give us a known point on the curve
	let scalar_bytes = hex!("0000000000000000000000000000000000000000000000000000000000000003");
	let scalar =
		BigUint::new_constant(&builder, &num_bigint::BigUint::from_bytes_be(&scalar_bytes))
			.zero_extend(&builder, 4); // Extend to 4 limbs for 256 bits

	// Expected result coordinates for 3*G
	// These are the x and y coordinates of 3 times the generator point
	let expected_x_bytes = hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
	let expected_y_bytes = hex!("388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672");

	let expected_x =
		BigUint::new_constant(&builder, &num_bigint::BigUint::from_bytes_be(&expected_x_bytes));
	let expected_y =
		BigUint::new_constant(&builder, &num_bigint::BigUint::from_bytes_be(&expected_y_bytes));

	// Get the generator point
	let generator = Secp256k1Affine::generator(&builder);

	// Perform scalar multiplication
	let result = scalar_mul_naive(&builder, &curve, 256, &scalar, generator);

	// Check that the result matches the expected point
	assert_eq(&builder, "result_x", &result.x, &expected_x);
	assert_eq(&builder, "result_y", &result.y, &expected_y);

	// Build and verify the circuit
	let cs = builder.build();
	let mut w = cs.new_witness_filler();
	assert!(cs.populate_wire_witness(&mut w).is_ok());

	// Also verify the point is not at infinity
	assert_eq!(w[result.is_point_at_infinity], Word::ZERO);
}
