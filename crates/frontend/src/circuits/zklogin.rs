use crate::{
	circuits::{
		base64::Base64UrlSafe,
		concat::{Concat, Term},
		fixed_byte_vec::FixedByteVec,
		jwt_claims::{Attribute, JwtClaims},
		sha256::Sha256,
	},
	compiler::{CircuitBuilder, Wire},
};

/// The configuration of the ZKLogin circuit.
///
/// Picking the numbers are a tradeoff. Picking a large number will require a larger circuit and
/// thus more proving time. Picking a small number may make some statements unprovable.
pub struct Config {
	/// Maximum byte length of the base64 decoded JWT header. Must be a multiple of 8.
	pub max_len_json_jwt_header: usize,
	/// Maximum byte length of the base64 decoded JWT payload. Must be a multiple of 8.
	pub max_len_json_jwt_payload: usize,
	/// Maximum byte length of the base64 decoded JWT signature. Must be a multiple of 8.
	pub max_len_jwt_signature: usize,
	pub max_len_jwt_sub: usize,
	pub max_len_jwt_aud: usize,
	pub max_len_jwt_iss: usize,
	pub max_len_salt: usize,
	pub max_len_nonce_r: usize,
	pub max_len_t_max: usize,
}

impl Config {
	pub fn max_len_base64_jwt_header(&self) -> usize {
		(self.max_len_json_jwt_header.div_ceil(3) * 4).next_multiple_of(8)
	}

	pub fn max_len_base64_jwt_payload(&self) -> usize {
		(self.max_len_json_jwt_payload.div_ceil(3) * 4).next_multiple_of(8)
	}

	pub fn max_len_base64_jwt_signature(&self) -> usize {
		(self.max_len_jwt_signature.div_ceil(3) * 4).next_multiple_of(8)
	}
}

/// A circuit that implements zk login.
pub struct ZkLogin {
	/// The subcircuit that verifies the JWT in the header.
	pub jwt_claims_header: JwtClaims,
	// /// The subcircuit that verifies the JWT in the payload.
	pub jwt_claims_payload: JwtClaims,
}

impl ZkLogin {
	pub fn new(b: &mut CircuitBuilder, config: Config) -> Self {
		let sub_byte_vec = FixedByteVec::new_inout(b, config.max_len_jwt_sub);
		let aud_byte_vec = FixedByteVec::new_inout(b, config.max_len_jwt_aud);
		let iss_byte_vec = FixedByteVec::new_inout(b, config.max_len_jwt_iss);
		let salt_byte_vec = FixedByteVec::new_inout(b, config.max_len_salt);

		let base64_jwt_header = FixedByteVec::new_witness(b, config.max_len_base64_jwt_header());
		let base64_jwt_payload = FixedByteVec::new_witness(b, config.max_len_base64_jwt_payload());
		let base64_jwt_signature =
			FixedByteVec::new_witness(b, config.max_len_base64_jwt_signature());

		let jwt_header = FixedByteVec::new_inout(b, config.max_len_json_jwt_header);
		let jwt_payload = FixedByteVec::new_witness(b, config.max_len_json_jwt_payload);
		let jwt_signature = FixedByteVec::new_witness(b, config.max_len_jwt_signature);

		let t_max = FixedByteVec::new_inout(b, config.max_len_t_max);
		let nonce_r = FixedByteVec::new_witness(b, config.max_len_nonce_r);

		let zkaddr: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
		let vk_u: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
		let nonce: [Wire; 4] = std::array::from_fn(|_| b.add_witness());

		// Decode JWT.
		// 1. header
		// 2. payload
		// 3. signature

		let _base64decode_check_header = Base64UrlSafe::new(
			b,
			config.max_len_json_jwt_header,
			jwt_header.data.clone(),
			base64_jwt_header.data.clone(),
			jwt_header.len,
		);
		let _base64decode_check_payload = Base64UrlSafe::new(
			b,
			config.max_len_json_jwt_payload,
			jwt_payload.data.clone(),
			base64_jwt_payload.data.clone(),
			jwt_payload.len,
		);
		let _base64decode_check_signature = Base64UrlSafe::new(
			b,
			config.max_len_jwt_signature,
			jwt_signature.data.clone(),
			base64_jwt_signature.data.clone(),
			jwt_signature.len,
		);

		// We need to check
		//
		// X = concat(JWT.sub, JWT.aud, JWT.iss, salt)
		// assert zkaddr == SHA256(X)
		let max_len_zkaddr_preimage = config.max_len_jwt_sub
			+ config.max_len_jwt_aud
			+ config.max_len_jwt_iss
			+ config.max_len_salt;
		let zkaddr_preimage = FixedByteVec::new_witness(b, max_len_zkaddr_preimage);

		let _zkaddr_preimage_concat = Concat::new(
			b,
			max_len_zkaddr_preimage,
			zkaddr_preimage.len,
			zkaddr_preimage.data.clone(),
			vec![
				Term {
					data: sub_byte_vec.data.clone(),
					len: sub_byte_vec.len,
					max_len: sub_byte_vec.max_len,
				},
				Term {
					data: aud_byte_vec.data.clone(),
					len: aud_byte_vec.len,
					max_len: aud_byte_vec.max_len,
				},
				Term {
					data: iss_byte_vec.data.clone(),
					len: iss_byte_vec.len,
					max_len: iss_byte_vec.max_len,
				},
				Term {
					data: salt_byte_vec.data,
					len: salt_byte_vec.len,
					max_len: salt_byte_vec.max_len,
				},
			],
		);

		let _zkaddr_sha256 = Sha256::new(
			b,
			zkaddr_preimage.max_len,
			zkaddr_preimage.len,
			zkaddr,
			zkaddr_preimage.data.clone(),
		);

		// nonce preimage is a result of concatenation of vk_u, T_max and r. vk_u is a public key
		let max_len_nonce_preimage = 32 + config.max_len_t_max + config.max_len_nonce_r;
		let nonce_preimage = FixedByteVec::new_witness(b, max_len_nonce_preimage);

		let _nonce_preimage_concat = Concat::new(
			b,
			max_len_nonce_preimage,
			nonce_preimage.len,
			nonce_preimage.data.clone(),
			vec![
				Term {
					data: vk_u.to_vec(),
					len: b.add_constant_64(32),
					max_len: 32,
				},
				Term {
					data: t_max.data.clone(),
					len: t_max.len,
					max_len: t_max.max_len,
				},
				Term {
					data: nonce_r.data.clone(),
					len: nonce_r.len,
					max_len: nonce_r.max_len,
				},
			],
		);
		let _nonce_sha256 = Sha256::new(
			b,
			nonce_preimage.max_len,
			nonce_preimage.len,
			nonce,
			nonce_preimage.data.clone(),
		);

		// Check signing payload. The JWT signed payload L is a concatenation of:
		//
		// L = concat(jwt.header | "." | jwt.payload)
		//
		let max_len_jwt_signing_payload = (config.max_len_base64_jwt_header()
			+ 1 + config.max_len_base64_jwt_payload())
		.next_multiple_of(8);
		let jwt_signing_payload = FixedByteVec::new_witness(b, max_len_jwt_signing_payload);
		let _jwt_signing_payload_concat = Concat::new(
			b,
			max_len_jwt_signing_payload,
			jwt_signing_payload.len,
			jwt_signing_payload.data.clone(),
			vec![
				Term {
					data: base64_jwt_header.data.clone(),
					len: base64_jwt_header.len,
					max_len: base64_jwt_header.max_len,
				},
				Term {
					data: vec![b.add_constant_zx_8(b'.')],
					len: b.add_constant_64(1),
					max_len: 8,
				},
				Term {
					data: base64_jwt_payload.data.clone(),
					len: base64_jwt_payload.len,
					max_len: base64_jwt_payload.max_len,
				},
			],
		);

		let jwt_claims_header = jwt_header_check(b, &jwt_header);
		let jwt_claims_payload =
			jwt_payload_check(b, &jwt_payload, &sub_byte_vec, &aud_byte_vec, &iss_byte_vec, &nonce);

		Self {
			jwt_claims_header,
			jwt_claims_payload,
		}
	}
}

// TODO: populate witness.

/// A check that verifies that JWT header has the expected constant values in the `alg` and `typ`
/// fields.
fn jwt_header_check(b: &CircuitBuilder, jwt_header: &FixedByteVec) -> JwtClaims {
	JwtClaims::new(
		b,
		jwt_header.max_len,
		jwt_header.len,
		jwt_header.data.clone(),
		vec![
			Attribute {
				name: "alg",
				len_value: b.add_inout(),
				value: vec![b.add_constant_64(u64::from_le_bytes(*b"RS256\0\0\0"))],
			},
			Attribute {
				name: "typ",
				len_value: b.add_inout(),
				value: vec![b.add_constant_64(u64::from_le_bytes(*b"JWT\0\0\0\0\0"))],
			},
		],
	)
}

/// A check that verifies that the payload has all the claimed values of `sub`, `aud`, `iss`
/// and `nonce`.
fn jwt_payload_check(
	b: &CircuitBuilder,
	jwt_payload: &FixedByteVec,
	sub_byte_vec: &FixedByteVec,
	aud_byte_vec: &FixedByteVec,
	iss_byte_vec: &FixedByteVec,
	nonce_byte_array: &[Wire; 4],
) -> JwtClaims {
	JwtClaims::new(
		b,
		jwt_payload.max_len,
		jwt_payload.len,
		jwt_payload.data.clone(),
		vec![
			Attribute {
				name: "sub",
				len_value: sub_byte_vec.len,
				value: sub_byte_vec.data.clone(),
			},
			Attribute {
				name: "aud",
				len_value: aud_byte_vec.len,
				value: aud_byte_vec.data.clone(),
			},
			Attribute {
				name: "iss",
				len_value: iss_byte_vec.len,
				value: iss_byte_vec.data.clone(),
			},
			Attribute {
				name: "nonce",
				len_value: b.add_constant_64(32),
				value: nonce_byte_array.to_vec(),
			},
		],
	)
}

#[test]
fn how_much() {
	let mut builder = CircuitBuilder::new();
	let config = Config {
		max_len_json_jwt_header: 264,
		max_len_json_jwt_payload: 504,
		max_len_jwt_signature: 264,
		max_len_jwt_sub: 72,
		max_len_jwt_aud: 72,
		max_len_jwt_iss: 72,
		max_len_salt: 72,
		max_len_nonce_r: 48,
		max_len_t_max: 48,
	};
	let _zklogin = ZkLogin::new(&mut builder, config);
	let circuit = builder.build();
	let cs = circuit.constraint_system();

	println!("Number of AND constraints: {}", cs.n_and_constraints());
	println!("Number of gates: {}", circuit.n_gates());
	println!("Length of value vec: {}", cs.value_vec_len());

	let mut w = circuit.new_witness_filler();
	let _ = circuit.populate_wire_witness(&mut w);
}
