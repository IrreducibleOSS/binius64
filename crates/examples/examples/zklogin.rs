use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::zklogin::{Config, ZkLogin},
	compiler::{CircuitBuilder, circuit::WitnessFiller},
};
use binius_utils::rayon::config::adjust_thread_pool;
use clap::Args;
use jwt_simple::prelude::*;
use rand::prelude::*;
use sha2::{Digest, Sha256};

struct ZkLoginExample {
	zklogin: ZkLogin,
}

#[derive(Args, Debug)]
struct Params {
	// Currently no circuit parameters - using default config
	// Could add max claim sizes, etc. here in the future
}

#[derive(Args, Debug)]
struct Instance {
	/// Subject claim value
	#[arg(long, default_value = "1234567890")]
	sub: String,

	/// Audience claim value
	#[arg(long, default_value = "4074087")]
	aud: String,

	/// Issuer claim value
	#[arg(long, default_value = "google.com")]
	iss: String,

	/// Salt value for zkaddr computation
	#[arg(long, default_value = "test_salt_value")]
	salt: String,
}

struct JwtGenerationResult {
	jwt: String,
	zkaddr_hash: [u8; 32],
	vk_u: [u8; 32],
	zkaddr_preimage: Vec<u8>,
	nonce_preimage: Vec<u8>,
	jwt_key_pair: RS256KeyPair,
}

impl JwtGenerationResult {
	fn generate(
		sub: &str,
		aud: &str,
		iss: &str,
		salt: &str,
		rng: &mut impl RngCore,
	) -> Result<Self> {
		// Generate VK_u (verifier public key)
		let mut vk_u = [0u8; 32];
		rng.fill_bytes(&mut vk_u);

		// Fixed values for nonce computation
		let t_max = b"t_max";
		let nonce_r = b"nonce_r";

		// Calculate zkaddr = SHA256(concat(sub, aud, iss, salt))
		let mut zkaddr_preimage = Vec::new();
		zkaddr_preimage.extend_from_slice(sub.as_bytes());
		zkaddr_preimage.extend_from_slice(aud.as_bytes());
		zkaddr_preimage.extend_from_slice(iss.as_bytes());
		zkaddr_preimage.extend_from_slice(salt.as_bytes());
		let zkaddr_hash: [u8; 32] = Sha256::digest(&zkaddr_preimage).into();

		// Calculate nonce = SHA256(concat(vk_u, t_max, nonce_r))
		let mut nonce_preimage = Vec::new();
		nonce_preimage.extend_from_slice(&vk_u);
		nonce_preimage.extend_from_slice(t_max);
		nonce_preimage.extend_from_slice(nonce_r);
		let nonce_hash: [u8; 32] = Sha256::digest(&nonce_preimage).into();
		let nonce_hash_base64 = BASE64_URL_SAFE_NO_PAD.encode(nonce_hash);

		// Generate JWT key pair
		let jwt_key_pair = RS256KeyPair::generate(2048).unwrap();

		// Create and sign JWT
		let claims = Claims::create(Duration::from_hours(2))
			.with_issuer(iss)
			.with_audience(aud)
			.with_subject(sub)
			.with_nonce(nonce_hash_base64);

		let jwt = jwt_key_pair.sign(claims).unwrap();

		Ok(Self {
			jwt,
			zkaddr_hash,
			vk_u,
			zkaddr_preimage,
			nonce_preimage,
			jwt_key_pair,
		})
	}
}

impl ExampleCircuit for ZkLoginExample {
	type Params = Params;
	type Instance = Instance;

	fn build(_params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let config = Config::default();
		let zklogin = ZkLogin::new(builder, config);

		Ok(Self { zklogin })
	}

	fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let mut rng = StdRng::seed_from_u64(0);

		// Generate JWT and related data
		let JwtGenerationResult {
			jwt,
			zkaddr_hash,
			vk_u,
			zkaddr_preimage,
			nonce_preimage,
			jwt_key_pair,
		} = JwtGenerationResult::generate(
			&instance.sub,
			&instance.aud,
			&instance.iss,
			&instance.salt,
			&mut rng,
		)?;

		// Parse JWT components
		let jwt_components = jwt.split(".").collect::<Vec<_>>();
		let [header_base64, payload_base64, signature_base64] = jwt_components.as_slice() else {
			anyhow::bail!("JWT should have format: header.payload.signature");
		};

		// Decode JWT components
		let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(signature_base64)?;
		let modulus_bytes = jwt_key_pair.public_key().to_components().n;
		let header = BASE64_URL_SAFE_NO_PAD.decode(header_base64)?;
		let payload = BASE64_URL_SAFE_NO_PAD.decode(payload_base64)?;

		ensure!(
			signature_bytes.len() == 256,
			"RSA signature must be 256 bytes, got {}",
			signature_bytes.len()
		);

		// Populate JWT components
		self.zklogin
			.populate_base64_jwt_header(w, header_base64.as_bytes());
		self.zklogin
			.populate_base64_jwt_payload(w, payload_base64.as_bytes());
		self.zklogin
			.populate_base64_jwt_signature(w, signature_base64.as_bytes());
		self.zklogin.populate_jwt_header(w, &header);
		self.zklogin.populate_jwt_header_attributes(w);
		self.zklogin.populate_jwt_payload(w, &payload);
		self.zklogin.populate_jwt_signature(w, &signature_bytes);

		// Populate claim values
		self.zklogin.populate_sub(w, instance.sub.as_bytes());
		self.zklogin.populate_aud(w, instance.aud.as_bytes());
		self.zklogin.populate_iss(w, instance.iss.as_bytes());
		self.zklogin.populate_salt(w, instance.salt.as_bytes());

		// Populate zkaddr
		self.zklogin.populate_zkaddr(w, &zkaddr_hash);
		self.zklogin.populate_zkaddr_preimage(w, &zkaddr_preimage);
		self.zklogin.populate_vk_u(w, &vk_u);
		self.zklogin.populate_t_max(w, b"t_max");
		self.zklogin.populate_nonce_r(w, b"nonce_r");

		// Populate nonce
		let nonce_hash: [u8; 32] = Sha256::digest(&nonce_preimage).into();
		let nonce_hash_base64 = BASE64_URL_SAFE_NO_PAD.encode(nonce_hash);
		self.zklogin.populate_nonce(w, &nonce_hash);
		self.zklogin.populate_nonce_preimage(w, &nonce_preimage);
		self.zklogin
			.populate_base64_jwt_payload_nonce(w, nonce_hash_base64.as_bytes());

		// Populate JWS signature verification data
		let message_str = format!("{header_base64}.{payload_base64}");
		let message_bytes = message_str.as_bytes();
		let hash = Sha256::digest(message_bytes);
		self.zklogin.populate_rsa_modulus(w, &modulus_bytes);
		self.zklogin
			.jwt_signature_verify
			.populate_len_bytes(w, message_bytes.len());
		self.zklogin
			.jwt_signature_verify
			.populate_message(w, message_bytes);
		self.zklogin
			.jwt_signature_verify
			.sha256
			.populate_digest(w, hash.into());
		self.zklogin.jwt_signature_verify.populate_intermediates(
			w,
			&signature_bytes,
			&modulus_bytes,
		);

		Ok(())
	}
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;
	adjust_thread_pool();

	Cli::<ZkLoginExample>::new("zklogin")
		.about("Circuit verifying knowledge of a valid OpenID Connect login")
		.run()
}
