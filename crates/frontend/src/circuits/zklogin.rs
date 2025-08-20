use binius_core::Word;

use crate::{
	circuits::{
		base64::Base64UrlSafe,
		concat::{Concat, Term},
		fixed_byte_vec::FixedByteVec,
		jwt_claims::{Attribute, JwtClaims},
		rs256::Rs256Verify,
		sha256::Sha256,
	},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::pack_bytes_into_wires_le,
};

/// The configuration of the ZKLogin circuit.
///
/// Picking the numbers are a tradeoff. Picking a large number will require a larger circuit and
/// thus more proving time. Picking a small number may make some statements unprovable.
#[derive(Debug)]
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

impl Default for Config {
	fn default() -> Self {
		Self {
			max_len_json_jwt_header: 264,
			max_len_json_jwt_payload: 504,
			max_len_jwt_signature: 264,
			max_len_jwt_sub: 72,
			max_len_jwt_aud: 72,
			max_len_jwt_iss: 72,
			max_len_salt: 72,
			max_len_nonce_r: 48,
			max_len_t_max: 48,
		}
	}
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
	/// The sub claim value
	pub sub: FixedByteVec,
	/// The aud claim value
	pub aud: FixedByteVec,
	/// The iss claim value
	pub iss: FixedByteVec,
	/// The salt value
	pub salt: FixedByteVec,
	/// The zkaddr (SHA256 hash of concat(sub, aud, iss, salt))
	pub zkaddr: [Wire; 4],
	/// The SHA256 circuit for zkaddr verification
	pub zkaddr_sha256: Sha256,
	/// The subcircuit that verifies the JWT header.
	pub jwt_claims_header: JwtClaims,
	/// The subcircuit that verifies the JWT in the payload.
	pub jwt_claims_payload: JwtClaims,
	/// The subcircuit that verifies the RS256 signature in the JWT.
	pub jwt_signature_verify: Rs256Verify,
	/// The JWT header
	pub base64_jwt_header: FixedByteVec,
	/// The JWT payload
	pub base64_jwt_payload: FixedByteVec,
	/// The JWT signature
	pub base64_jwt_signature: FixedByteVec,
	/// The decoded JWT header
	pub jwt_header: FixedByteVec,
	/// The decoded jwt_payload
	pub jwt_payload: FixedByteVec,
	/// The decoded jwt_signature (264 bytes for Base64, little-endian packing)
	pub jwt_signature: FixedByteVec,
	/// The base64 encoded nonce
	pub base64_jwt_payload_nonce: [Wire; 8],
	/// The SHA256 circuit for nonce verification
	pub nonce_sha256: Sha256,
	/// The nonce value (32 bytes SHA256 hash)
	pub nonce: [Wire; 4],
	/// The vk_u public key (32 bytes)
	pub vk_u: [Wire; 4],
	/// The t_max value
	pub t_max: FixedByteVec,
	/// The nonce_r value
	pub nonce_r: FixedByteVec,
}

impl ZkLogin {
	pub fn new(b: &mut CircuitBuilder, config: Config) -> Self {
		let sub = FixedByteVec::new_inout(b, config.max_len_jwt_sub);
		let aud = FixedByteVec::new_inout(b, config.max_len_jwt_aud);
		let iss = FixedByteVec::new_inout(b, config.max_len_jwt_iss);
		let salt = FixedByteVec::new_inout(b, config.max_len_salt);

		let base64_jwt_header = FixedByteVec::new_inout(b, config.max_len_base64_jwt_header());
		let base64_jwt_payload = FixedByteVec::new_inout(b, config.max_len_base64_jwt_payload());
		let base64_jwt_signature =
			FixedByteVec::new_inout(b, config.max_len_base64_jwt_signature());

		let jwt_header = FixedByteVec::new_inout(b, config.max_len_json_jwt_header);
		let jwt_payload = FixedByteVec::new_witness(b, config.max_len_json_jwt_payload);
		let jwt_signature = FixedByteVec::new_witness(b, config.max_len_jwt_signature);

		let t_max = FixedByteVec::new_inout(b, config.max_len_t_max);
		let nonce_r = FixedByteVec::new_witness(b, config.max_len_nonce_r);

		let zkaddr: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
		let vk_u: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
		let nonce: [Wire; 4] = std::array::from_fn(|_| b.add_witness());

		// The base64 encoded nonce in the JWT payload. This must have
		// 8 wires = 64 bytes to accommodate the 43-byte base64 nonce with padding.
		let base64_jwt_payload_nonce: [Wire; 8] = std::array::from_fn(|_| b.add_witness());

		// RSA modulus as public input (256 bytes for 2048-bit RSA)
		let rsa_modulus = FixedByteVec::new_inout(b, 256);

		// Decode JWT.
		// 1. header
		// 2. payload
		// 3. signature

		let _base64decode_check_header = Base64UrlSafe::new(
			&b.subcircuit("base64_check_header"),
			config.max_len_json_jwt_header,
			jwt_header.data.clone(),
			base64_jwt_header.data.clone(),
			jwt_header.len,
		);
		let _base64decode_check_payload = Base64UrlSafe::new(
			&b.subcircuit("base64_check_payload"),
			config.max_len_json_jwt_payload,
			jwt_payload.data.clone(),
			base64_jwt_payload.data.clone(),
			jwt_payload.len,
		);
		let _base64decode_check_signature = Base64UrlSafe::new(
			&b.subcircuit("base64_check_signature"),
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

		// Create SHA256 verification for zkaddr first
		let zkaddr_preimage_len = b.add_witness();
		let zkaddr_sha256_message: Vec<Wire> = (0..max_len_zkaddr_preimage / 8)
			.map(|_| b.add_witness())
			.collect();
		let zkaddr_sha256 = Sha256::new(
			&b.subcircuit("zkaddr_sha256"),
			zkaddr_preimage_len,
			zkaddr,
			zkaddr_sha256_message,
		);

		let zkaddr_preimage_le_wires = zkaddr_sha256.message_to_le_wires(b);
		let zkaddr_joined_words = max_len_zkaddr_preimage / 8;
		let zkaddr_joined_le = zkaddr_preimage_le_wires[..zkaddr_joined_words].to_vec();

		// Create the concatenation that outputs to the LE wires
		let _zkaddr_preimage_concat = Concat::new(
			&b.subcircuit("zkaddr_preimage_concat"),
			max_len_zkaddr_preimage,
			zkaddr_preimage_len,
			zkaddr_joined_le,
			vec![
				Term {
					data: sub.data.clone(),
					len: sub.len,
					max_len: sub.max_len,
				},
				Term {
					data: aud.data.clone(),
					len: aud.len,
					max_len: aud.max_len,
				},
				Term {
					data: iss.data.clone(),
					len: iss.len,
					max_len: iss.max_len,
				},
				Term {
					data: salt.data.clone(),
					len: salt.len,
					max_len: salt.max_len,
				},
			],
		);

		// We need to check:
		//
		// nonce_preimage = concat(vk_u, T_max, r) where vk_u is a public key
		// assert nonce = SHA256(nonce_preimage)
		// assert nonce = base64_decode(base64_jwt_payload_nonce)
		let max_len_nonce_preimage = 32 + config.max_len_t_max + config.max_len_nonce_r;

		// Create SHA256 verification for nonce first
		let nonce_preimage_len = b.add_witness();
		let nonce_sha256_message: Vec<Wire> = (0..max_len_nonce_preimage / 8)
			.map(|_| b.add_witness())
			.collect();
		let nonce_sha256 = Sha256::new(
			&b.subcircuit("nonce_sha256"),
			nonce_preimage_len,
			nonce,
			nonce_sha256_message,
		);

		let nonce_preimage_le_wires = nonce_sha256.message_to_le_wires(b);
		let nonce_joined_words = max_len_nonce_preimage / 8;
		let nonce_joined_le = nonce_preimage_le_wires[..nonce_joined_words].to_vec();
		let _nonce_preimage_concat = Concat::new(
			&b.subcircuit("nonce_preimage_concat"),
			max_len_nonce_preimage,
			nonce_preimage_len,
			nonce_joined_le,
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

		let nonce_le = nonce_sha256.digest_to_le_wires(b);

		// Base64 requires 48 bytes (6 wires) for alignment, so add zero padding
		let zero = b.add_constant(Word::ZERO);
		let nonce_le_for_base64: Vec<Wire> = nonce_le.into_iter().chain([zero, zero]).collect();

		// The zklogin nonce claim is Base64 URL encoded without padding (i.e.
		// in the same way as JWS components)
		// <https://github.com/MystenLabs/ts-sdks/blob/eb23fc1c122a1495e52d0bd613bf5e8e6eb816cc/packages/typescript/src/zklogin/nonce.ts#L33>
		//
		// The nonce is 32 bytes which encodes to 43 base64 characters.
		// Base64UrlSafe requires max_len_decoded to be a multiple of 24,
		// so we use 48 bytes (6 wires) for decoded and 64 bytes (8 wires) for encoded.
		let base64_check_nonce_builder = b.subcircuit("base64_check_nonce");
		let _base64decode_check_nonce = Base64UrlSafe::new(
			&base64_check_nonce_builder,
			48,
			nonce_le_for_base64.clone(),
			base64_jwt_payload_nonce.to_vec(),
			base64_check_nonce_builder.add_constant_64(32),
		);

		// Check signing payload. The JWT signed payload L is a concatenation of:
		//
		// L = concat(jwt.header | "." | jwt.payload)
		//
		let max_len_jwt_signing_payload = (config.max_len_base64_jwt_header()
			+ 1 + config.max_len_base64_jwt_payload())
		.next_multiple_of(8);

		// Create witness wires for the JWT signing payload in SHA256 format
		let jwt_signing_payload_sha256_len = b.add_witness();
		let n_words_jwt_signing_payload_sha256 = max_len_jwt_signing_payload.div_ceil(8);
		let jwt_signing_payload_sha256_message: Vec<Wire> = (0..n_words_jwt_signing_payload_sha256)
			.map(|_| b.add_witness())
			.collect();

		let jwt_signing_payload = FixedByteVec::new(
			jwt_signing_payload_sha256_message.clone(),
			jwt_signing_payload_sha256_len,
		);

		let jwt_signature_verify =
			Rs256Verify::new(b, jwt_signing_payload, jwt_signature.clone(), rsa_modulus);

		let jwt_signing_payload_le_wires = jwt_signature_verify.sha256.message_to_le_wires(b);
		let signing_joined_words = max_len_jwt_signing_payload / 8;
		let signing_joined_le = jwt_signing_payload_le_wires[..signing_joined_words].to_vec();
		let _jwt_signing_payload_concat = Concat::new(
			&b.subcircuit("jwt_signing_payload_concat"),
			max_len_jwt_signing_payload,
			jwt_signing_payload_sha256_len,
			signing_joined_le,
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
			jwt_payload_check(b, &jwt_payload, &sub, &aud, &iss, &base64_jwt_payload_nonce);

		Self {
			sub,
			aud,
			iss,
			salt,
			zkaddr,
			zkaddr_sha256,
			jwt_claims_header,
			jwt_claims_payload,
			jwt_signature_verify,
			base64_jwt_header,
			base64_jwt_payload,
			base64_jwt_signature,
			jwt_header,
			jwt_payload,
			jwt_signature,
			base64_jwt_payload_nonce,
			nonce_sha256,
			nonce,
			vk_u,
			t_max,
			nonce_r,
		}
	}

	pub fn populate_sub(&self, w: &mut WitnessFiller, sub_bytes: &[u8]) {
		self.sub.populate_bytes_le(w, sub_bytes);
	}

	pub fn populate_aud(&self, w: &mut WitnessFiller, aud_bytes: &[u8]) {
		self.aud.populate_bytes_le(w, aud_bytes);
	}

	pub fn populate_iss(&self, w: &mut WitnessFiller, iss_bytes: &[u8]) {
		self.iss.populate_bytes_le(w, iss_bytes);
	}

	pub fn populate_salt(&self, w: &mut WitnessFiller, salt_bytes: &[u8]) {
		self.salt.populate_bytes_le(w, salt_bytes);
	}

	pub fn populate_zkaddr(&self, w: &mut WitnessFiller, zkaddr_hash: &[u8; 32]) {
		self.zkaddr_sha256.populate_digest(w, *zkaddr_hash);
	}

	pub fn populate_zkaddr_preimage(&self, w: &mut WitnessFiller, zkaddr_preimage: &[u8]) {
		self.zkaddr_sha256.populate_len(w, zkaddr_preimage.len());
		self.zkaddr_sha256.populate_message(w, zkaddr_preimage);
	}

	pub fn populate_jwt_header(&self, w: &mut WitnessFiller, header_bytes: &[u8]) {
		self.jwt_header.populate_bytes_le(w, header_bytes);
	}

	pub fn populate_jwt_payload(&self, w: &mut WitnessFiller, payload_bytes: &[u8]) {
		self.jwt_payload.populate_bytes_le(w, payload_bytes);
	}

	pub fn populate_jwt_signature(&self, w: &mut WitnessFiller, signature_bytes: &[u8]) {
		assert_eq!(signature_bytes.len(), 256, "RSA signature must be 256 bytes");
		self.jwt_signature.populate_bytes_le(w, signature_bytes);
	}

	pub fn populate_base64_jwt_header(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		self.base64_jwt_header.populate_bytes_le(w, bytes);
	}

	pub fn populate_base64_jwt_payload(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		self.base64_jwt_payload.populate_bytes_le(w, bytes);
	}

	pub fn populate_base64_jwt_signature(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		let mut padded = bytes.to_vec();
		let expected_len = (self.jwt_signature.max_len / 3) * 4; // 264/3*4 = 352
		padded.resize(expected_len, 0);
		self.base64_jwt_signature.populate_bytes_le(w, &padded);
	}

	pub fn populate_rsa_modulus(&self, w: &mut WitnessFiller, modulus_bytes: &[u8]) {
		self.jwt_signature_verify
			.modulus
			.populate_bytes_le(w, modulus_bytes);
	}

	pub fn populate_jwt_header_attributes(&self, w: &mut WitnessFiller) {
		// Populate the expected lengths for "alg" and "typ" attributes
		self.jwt_claims_header.attributes[0].populate_len_value(w, 5); // "RS256" is 5 bytes
		self.jwt_claims_header.attributes[1].populate_len_value(w, 3); // "JWT" is 3 bytes
	}

	pub fn populate_nonce(&self, w: &mut WitnessFiller, nonce_hash: &[u8; 32]) {
		self.nonce_sha256.populate_digest(w, *nonce_hash);
	}

	pub fn populate_nonce_preimage(&self, w: &mut WitnessFiller, nonce_preimage: &[u8]) {
		self.nonce_sha256.populate_len(w, nonce_preimage.len());
		self.nonce_sha256.populate_message(w, nonce_preimage);
	}

	pub fn populate_vk_u(&self, w: &mut WitnessFiller, vk_u_bytes: &[u8; 32]) {
		pack_bytes_into_wires_le(w, &self.vk_u, vk_u_bytes);
	}

	pub fn populate_t_max(&self, w: &mut WitnessFiller, t_max_bytes: &[u8]) {
		self.t_max.populate_bytes_le(w, t_max_bytes);
	}

	pub fn populate_nonce_r(&self, w: &mut WitnessFiller, nonce_r_bytes: &[u8]) {
		self.nonce_r.populate_bytes_le(w, nonce_r_bytes);
	}

	pub fn populate_base64_jwt_payload_nonce(&self, w: &mut WitnessFiller, base64_nonce: &[u8]) {
		// The base64 nonce is 43 characters, but we need to pad to 64 bytes (8 wires)
		let mut padded = vec![0u8; 64];
		padded[..base64_nonce.len().min(64)]
			.copy_from_slice(&base64_nonce[..base64_nonce.len().min(64)]);
		pack_bytes_into_wires_le(w, &self.base64_jwt_payload_nonce, &padded);
	}
}

/// A check that verifies that JWT header has the expected constant values in the `alg` and `typ`
/// fields.
fn jwt_header_check(b: &CircuitBuilder, jwt_header: &FixedByteVec) -> JwtClaims {
	JwtClaims::new(
		&b.subcircuit("jwt_claims_header"),
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
	base64_nonce: &[Wire; 8],
) -> JwtClaims {
	JwtClaims::new(
		&b.subcircuit("jwt_claims_payload"),
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
				len_value: b.add_constant_64(43), /* Base64 encoded 32 bytes without padding = 43
				                                   * chars */
				// Only use the first 6 wires (48 bytes) which contain the 43-byte nonce
				value: base64_nonce[..6].to_vec(),
			},
		],
	)
}

#[cfg(test)]
mod tests {

	use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
	use rand::{SeedableRng, TryRngCore, rngs::StdRng};
	use sha2::{Digest, Sha256};

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	#[test]
	fn test_zklogin_with_jwt_population() {
		use jwt_simple::prelude::*;

		let jwt_key_pair = RS256KeyPair::generate(2048).unwrap();

		let mut rng = StdRng::seed_from_u64(42);
		let mut vk_u = [0u8; 32];
		rng.try_fill_bytes(&mut vk_u).unwrap();

		let iss = "google.com";
		let aud = "4074087";
		let sub = "1234567890";
		let salt = "test_salt_value";
		let t_max = b"t_max";
		let nonce_r = b"nonce_r";

		// Calculate zkaddr = SHA256(concat(sub, aud, iss, salt))
		let mut zkaddr_preimage = Vec::new();
		zkaddr_preimage.extend_from_slice(sub.as_bytes());
		zkaddr_preimage.extend_from_slice(aud.as_bytes());
		zkaddr_preimage.extend_from_slice(iss.as_bytes());
		zkaddr_preimage.extend_from_slice(salt.as_bytes());
		let zkaddr_hash = Sha256::digest(&zkaddr_preimage);

		// Calculate nonce = SHA256(concat(vk_u, t_max, nonce_r))
		let mut nonce_preimage = Vec::new();
		nonce_preimage.extend_from_slice(&vk_u);
		nonce_preimage.extend_from_slice(t_max);
		nonce_preimage.extend_from_slice(nonce_r);
		let nonce_hash = Sha256::digest(&nonce_preimage);
		let nonce_hash_base64 = BASE64_URL_SAFE_NO_PAD.encode(nonce_hash);

		let claims = Claims::create(Duration::from_hours(2))
			.with_issuer(iss)
			.with_audience(aud)
			.with_subject(sub)
			.with_nonce(nonce_hash_base64.clone());
		let jwt = jwt_key_pair.sign(claims).unwrap();
		let jwt_components = jwt.split(".").collect::<Vec<_>>();
		let [header_base64, payload_base64, signature_base64] = jwt_components.as_slice() else {
			panic!("jwt should be header.payload.signature")
		};

		let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(signature_base64).unwrap();
		let modulus_bytes = jwt_key_pair.public_key().to_components().n;

		let header = BASE64_URL_SAFE_NO_PAD.decode(header_base64).unwrap();
		let payload = BASE64_URL_SAFE_NO_PAD.decode(payload_base64).unwrap();

		let mut builder = CircuitBuilder::new();
		let config = Config::default();
		let zklogin = ZkLogin::new(&mut builder, config);
		let circuit = builder.build();

		let mut w = circuit.new_witness_filler();

		zklogin.populate_base64_jwt_header(&mut w, header_base64.as_bytes());
		zklogin.populate_base64_jwt_payload(&mut w, payload_base64.as_bytes());
		zklogin.populate_base64_jwt_signature(&mut w, signature_base64.as_bytes());
		zklogin.populate_jwt_header(&mut w, &header);
		zklogin.populate_jwt_header_attributes(&mut w);
		zklogin.populate_jwt_payload(&mut w, &payload);
		zklogin.populate_jwt_signature(&mut w, &signature_bytes);

		zklogin.populate_sub(&mut w, sub.as_bytes());
		zklogin.populate_aud(&mut w, aud.as_bytes());
		zklogin.populate_iss(&mut w, iss.as_bytes());
		zklogin.populate_salt(&mut w, salt.as_bytes());

		// zkaddr
		zklogin.populate_zkaddr(&mut w, &zkaddr_hash.into());
		zklogin.populate_zkaddr_preimage(&mut w, &zkaddr_preimage);
		zklogin.populate_vk_u(&mut w, &vk_u);
		zklogin.populate_t_max(&mut w, t_max);
		zklogin.populate_nonce_r(&mut w, nonce_r);

		// nonce
		zklogin.populate_nonce(&mut w, &nonce_hash.into());
		zklogin.populate_nonce_preimage(&mut w, &nonce_preimage);
		zklogin.populate_base64_jwt_payload_nonce(&mut w, nonce_hash_base64.as_bytes());

		// JWS signature payload
		let message_str = format!("{header_base64}.{payload_base64}");
		let message = message_str.as_bytes();
		let hash = Sha256::digest(message);
		zklogin.populate_rsa_modulus(&mut w, &modulus_bytes);
		zklogin
			.jwt_signature_verify
			.populate_message_len(&mut w, message.len());
		zklogin
			.jwt_signature_verify
			.populate_message(&mut w, message);
		zklogin
			.jwt_signature_verify
			.sha256
			.populate_digest(&mut w, hash.into());
		zklogin.jwt_signature_verify.populate_intermediates(
			&mut w,
			&signature_bytes,
			&modulus_bytes,
		);

		circuit.populate_wire_witness(&mut w).unwrap();
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.value_vec).unwrap();
	}
}
