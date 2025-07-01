// Copyright 2024-2025 Irreducible Inc.

use std::{fs::File, io::Write, iter::repeat_with, slice};

use binius_field::TowerField;
use binius_utils::{DeserializeBytes, SerializationMode, SerializeBytes};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{
	error::Error,
	fiat_shamir::{Challenger, FiatShamirBuf},
};
use crate::fiat_shamir::{CanSample, CanSampleBits, sample_bits_reader};

/// Verifier transcript over some Challenger that reads from the internal tape and `CanSample<F:
/// TowerField>`
///
/// You must manually call the destructor with `finalize()` to check anything that's written is
/// fully read out
#[derive(Debug, Clone)]
pub struct VerifierTranscript<Challenger> {
	combined: FiatShamirBuf<Bytes, Challenger>,
	debug_assertions: bool,
}

impl<Challenger_: Default + Challenger> VerifierTranscript<Challenger_> {
	pub fn new(vec: Vec<u8>) -> Self {
		Self {
			combined: FiatShamirBuf {
				challenger: Challenger_::default(),
				buffer: Bytes::from(vec),
			},
			debug_assertions: cfg!(debug_assertions),
		}
	}
}

impl<Challenger_: Challenger> VerifierTranscript<Challenger_> {
	pub fn finalize(self) -> Result<(), Error> {
		if self.combined.buffer.has_remaining() {
			return Err(Error::TranscriptNotEmpty {
				remaining: self.combined.buffer.remaining(),
			});
		}
		Ok(())
	}

	pub const fn set_debug(&mut self, debug: bool) {
		self.debug_assertions = debug;
	}

	/// Returns a writable buffer that only observes the data written, without reading it from the
	/// proof tape.
	///
	/// This method should be used to observe the input statement.
	pub fn observe<'a, 'b>(&'a mut self) -> TranscriptWriter<'b, impl BufMut + 'b>
	where
		'a: 'b,
	{
		TranscriptWriter {
			buffer: self.combined.challenger.observer(),
			debug_assertions: self.debug_assertions,
		}
	}

	/// Returns a readable buffer that only reads the data from the proof tape, without observing
	/// it.
	///
	/// This method should only be used to read advice that was previously written to the transcript
	/// as an observed message.
	pub fn decommitment(&mut self) -> TranscriptReader<'_, impl Buf + '_> {
		TranscriptReader {
			buffer: &mut self.combined.buffer,
			debug_assertions: self.debug_assertions,
		}
	}

	/// Returns a readable buffer that observes the data read.
	///
	/// This method should be used by default to read verifier messages in an interactive protocol.
	pub fn message<'a, 'b>(&'a mut self) -> TranscriptReader<'b, impl Buf>
	where
		'a: 'b,
	{
		TranscriptReader {
			buffer: &mut self.combined,
			debug_assertions: self.debug_assertions,
		}
	}
}

// Useful warnings to see if we are neglecting to read any advice or transcript entirely
impl<Challenger> Drop for VerifierTranscript<Challenger> {
	fn drop(&mut self) {
		if self.combined.buffer.has_remaining() {
			tracing::warn!(
				"Transcript reader is not fully read out: {:?} bytes left",
				self.combined.buffer.remaining()
			)
		}
	}
}

impl<F, Challenger_> CanSample<F> for VerifierTranscript<Challenger_>
where
	F: TowerField,
	Challenger_: Challenger,
{
	fn sample(&mut self) -> F {
		let mode = SerializationMode::CanonicalTower;
		DeserializeBytes::deserialize(self.combined.challenger.sampler(), mode)
			.expect("challenger has infinite buffer")
	}
}

pub struct TranscriptReader<'a, B: Buf> {
	buffer: &'a mut B,
	debug_assertions: bool,
}

impl<B: Buf> TranscriptReader<'_, B> {
	pub const fn buffer(&mut self) -> &mut B {
		self.buffer
	}

	pub fn read<T: DeserializeBytes>(&mut self) -> Result<T, Error> {
		let mode = SerializationMode::CanonicalTower;
		T::deserialize(self.buffer(), mode).map_err(Into::into)
	}

	pub fn read_vec<T: DeserializeBytes>(&mut self, n: usize) -> Result<Vec<T>, Error> {
		let mode = SerializationMode::CanonicalTower;
		let mut buffer = self.buffer();
		repeat_with(move || T::deserialize(&mut buffer, mode).map_err(Into::into))
			.take(n)
			.collect()
	}

	pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), Error> {
		let buffer = self.buffer();
		if buffer.remaining() < buf.len() {
			return Err(Error::NotEnoughBytes);
		}
		buffer.copy_to_slice(buf);
		Ok(())
	}

	pub fn read_scalar<F: TowerField>(&mut self) -> Result<F, Error> {
		let mut out = F::default();
		self.read_scalar_slice_into(slice::from_mut(&mut out))?;
		Ok(out)
	}

	pub fn read_scalar_slice_into<F: TowerField>(&mut self, buf: &mut [F]) -> Result<(), Error> {
		let mut buffer = self.buffer();
		for elem in buf {
			let mode = SerializationMode::CanonicalTower;
			*elem = DeserializeBytes::deserialize(&mut buffer, mode)?;
		}
		Ok(())
	}

	pub fn read_scalar_slice<F: TowerField>(&mut self, len: usize) -> Result<Vec<F>, Error> {
		let mut elems = vec![F::default(); len];
		self.read_scalar_slice_into(&mut elems)?;
		Ok(elems)
	}

	pub fn read_debug(&mut self, msg: &str) {
		if self.debug_assertions {
			let msg_bytes = msg.as_bytes();
			let mut buffer = vec![0; msg_bytes.len()];
			assert!(self.read_bytes(&mut buffer).is_ok());
			assert_eq!(msg_bytes, buffer);
		}
	}
}

/// Prover transcript over some Challenger that writes to the internal tape and `CanSample<F:
/// TowerField>`
///
/// A Transcript is an abstraction over Fiat-Shamir so the prover and verifier can send and receive
/// data.
#[derive(Debug)]
pub struct ProverTranscript<Challenger> {
	combined: FiatShamirBuf<BytesMut, Challenger>,
	debug_assertions: bool,
}

impl<Challenger_: Default + Challenger> ProverTranscript<Challenger_> {
	/// Creates a new prover transcript.
	///
	/// By default debug assertions are set to the feature flag `debug_assertions`. You may also
	/// change the debug flag with [`Self::set_debug`].
	pub fn new() -> Self {
		Self {
			combined: Default::default(),
			debug_assertions: cfg!(debug_assertions),
		}
	}

	pub fn into_verifier(self) -> VerifierTranscript<Challenger_> {
		let transcript = self.finalize();

		VerifierTranscript::new(transcript)
	}
}

impl<Challenger_: Default + Challenger> Default for ProverTranscript<Challenger_> {
	fn default() -> Self {
		Self::new()
	}
}

impl<Challenger_: Challenger> ProverTranscript<Challenger_> {
	pub fn finalize(self) -> Vec<u8> {
		let transcript = self.combined.buffer.to_vec();

		// Dumps the transcript to the path set in the BINIUS_DUMP_PROOF env variable.
		if let Ok(path) = std::env::var("BINIUS_DUMP_PROOF") {
			let path = if cfg!(test) {
				// Because tests may run simultaneously, each test includes its name in the file
				// name to avoid collisions.
				let current_thread = std::thread::current();
				let test_name = current_thread.name().unwrap_or("unknown");
				// Adjust "./" to "../../" to ensure files are saved in the project root rather than
				// the package root.
				let path = if let Some(stripped) = path.strip_prefix("./") {
					format!("../../{stripped}",)
				} else {
					path
				};
				std::fs::create_dir_all(&path)
					.unwrap_or_else(|_| panic!("Failed to create directories for path: {path}",));
				format!("{path}/{test_name}.bin")
			} else {
				path
			};

			let mut file = File::create(&path)
				.unwrap_or_else(|_| panic!("Failed to create proof dump file: {path}"));
			file.write_all(&transcript)
				.expect("Failed to write proof to dump file");
		}
		transcript
	}

	/// Sets the debug flag.
	///
	/// This flag is used to enable debug assertions in the [`TranscriptReader`] and
	/// [`TranscriptWriter`] methods.
	pub const fn set_debug(&mut self, debug: bool) {
		self.debug_assertions = debug;
	}

	/// Returns a writeable buffer that only observes the data written, without writing it to the
	/// proof tape.
	///
	/// This method should be used to observe the input statement.
	pub fn observe<'a, 'b>(&'a mut self) -> TranscriptWriter<'b, impl BufMut + 'b>
	where
		'a: 'b,
	{
		TranscriptWriter {
			buffer: self.combined.challenger.observer(),
			debug_assertions: self.debug_assertions,
		}
	}

	/// Returns a writeable buffer that only writes the data to the proof tape, without observing
	/// it.
	///
	/// This method should only be used to write openings of commitments that were already written
	/// to the transcript as an observed message. For example, in the FRI protocol, the prover sends
	/// a Merkle tree root as a commitment, and later sends leaf openings. The leaf openings should
	/// be written using [`Self::decommitment`] because they are verified with respect to the
	/// previously sent Merkle root.
	pub fn decommitment(&mut self) -> TranscriptWriter<'_, impl BufMut> {
		TranscriptWriter {
			buffer: &mut self.combined.buffer,
			debug_assertions: self.debug_assertions,
		}
	}

	/// Returns a writeable buffer that observes the data written and writes it to the proof tape.
	///
	/// This method should be used by default to write prover messages in an interactive protocol.
	pub fn message<'a, 'b>(&'a mut self) -> TranscriptWriter<'b, impl BufMut>
	where
		'a: 'b,
	{
		TranscriptWriter {
			buffer: &mut self.combined,
			debug_assertions: self.debug_assertions,
		}
	}
}

pub struct TranscriptWriter<'a, B: BufMut> {
	buffer: &'a mut B,
	debug_assertions: bool,
}

impl<B: BufMut> TranscriptWriter<'_, B> {
	pub const fn buffer(&mut self) -> &mut B {
		self.buffer
	}

	pub fn write<T: SerializeBytes>(&mut self, value: &T) {
		self.proof_size_event_wrapper(|buffer| {
			value
				.serialize(buffer, SerializationMode::CanonicalTower)
				.expect("TODO: propagate error");
		});
	}

	pub fn write_slice<T: SerializeBytes>(&mut self, values: &[T]) {
		self.proof_size_event_wrapper(|buffer| {
			for value in values {
				value
					.serialize(&mut *buffer, SerializationMode::CanonicalTower)
					.expect("TODO: propagate error");
			}
		});
	}

	pub fn write_bytes(&mut self, data: &[u8]) {
		self.proof_size_event_wrapper(|buffer| {
			buffer.put_slice(data);
		});
	}

	pub fn write_scalar<F: TowerField>(&mut self, f: F) {
		self.write_scalar_slice(slice::from_ref(&f));
	}

	pub fn write_scalar_iter<F: TowerField>(&mut self, it: impl IntoIterator<Item = F>) {
		self.proof_size_event_wrapper(move |buffer| {
			for elem in it {
				SerializeBytes::serialize(&elem, &mut *buffer, SerializationMode::CanonicalTower)
					.expect("TODO: propagate error");
			}
		});
	}

	pub fn write_scalar_slice<F: TowerField>(&mut self, elems: &[F]) {
		self.write_scalar_iter(elems.iter().copied());
	}

	pub fn write_debug(&mut self, msg: &str) {
		if self.debug_assertions {
			self.write_bytes(msg.as_bytes())
		}
	}

	fn proof_size_event_wrapper<F: FnOnce(&mut B)>(&mut self, f: F) {
		let buffer = self.buffer();
		let start_bytes = buffer.remaining_mut();
		f(buffer);
		let end_bytes = buffer.remaining_mut();
		tracing::event!(name: "incremental_proof_size", tracing::Level::INFO, counter=true, incremental=true, value=start_bytes - end_bytes);
	}
}

impl<F, Challenger_> CanSample<F> for ProverTranscript<Challenger_>
where
	F: TowerField,
	Challenger_: Challenger,
{
	fn sample(&mut self) -> F {
		let mode = SerializationMode::CanonicalTower;
		DeserializeBytes::deserialize(self.combined.challenger.sampler(), mode)
			.expect("challenger has infinite buffer")
	}
}

impl<Challenger_> CanSampleBits<u32> for ProverTranscript<Challenger_>
where
	Challenger_: Challenger,
{
	fn sample_bits(&mut self, bits: usize) -> u32 {
		sample_bits_reader(self.combined.challenger.sampler(), bits)
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{
		AESTowerField8b, AESTowerField16b, AESTowerField32b, AESTowerField128b, BinaryField8b,
		BinaryField32b, BinaryField64b, BinaryField128b, BinaryField128bPolyval,
	};
	use blake2::Blake2b;
	use bytes::{Buf, BufMut};
	use digest::consts::U32;
	use rand::prelude::*;

	use super::*;
	use crate::fiat_shamir::{CanSample, Challenger, HasherChallenger};

	type Blake2b256 = Blake2b<U32>;

	#[test]
	fn test_transcript_interactions() {
		let mut prover_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::new();
		let mut writable = prover_transcript.message();

		writable.write_scalar(BinaryField8b::new(0x96));
		writable.write_scalar(BinaryField32b::new(0xDEADBEEF));
		writable.write_scalar(BinaryField128b::new(0x55669900112233550000CCDDFFEEAABB));
		let sampled_fanpaar1: BinaryField128b = prover_transcript.sample();

		let mut writable = prover_transcript.message();

		writable.write_scalar(AESTowerField8b::new(0x52));
		writable.write_scalar(AESTowerField32b::new(0x12345678));
		writable.write_scalar(AESTowerField128b::new(0xDDDDBBBBCCCCAAAA2222999911117777));

		let sampled_aes1: AESTowerField16b = prover_transcript.sample();

		prover_transcript
			.message()
			.write_scalar(BinaryField128bPolyval::new(0xFFFF12345678DDDDEEEE87654321AAAA));
		let sampled_polyval1: BinaryField128bPolyval = prover_transcript.sample();

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut readable = verifier_transcript.message();

		let fp_8: BinaryField8b = readable.read_scalar().unwrap();
		let fp_32: BinaryField32b = readable.read_scalar().unwrap();
		let fp_128: BinaryField128b = readable.read_scalar().unwrap();

		assert_eq!(fp_8.val(), 0x96);
		assert_eq!(fp_32.val(), 0xDEADBEEF);
		assert_eq!(fp_128.val(), 0x55669900112233550000CCDDFFEEAABB);

		let sampled_fanpaar1_res: BinaryField128b = verifier_transcript.sample();

		assert_eq!(sampled_fanpaar1_res, sampled_fanpaar1);

		let mut readable = verifier_transcript.message();

		let aes_8: AESTowerField8b = readable.read_scalar().unwrap();
		let aes_32: AESTowerField32b = readable.read_scalar().unwrap();
		let aes_128: AESTowerField128b = readable.read_scalar().unwrap();

		assert_eq!(aes_8.val(), 0x52);
		assert_eq!(aes_32.val(), 0x12345678);
		assert_eq!(aes_128.val(), 0xDDDDBBBBCCCCAAAA2222999911117777);

		let sampled_aes_res: AESTowerField16b = verifier_transcript.sample();

		assert_eq!(sampled_aes_res, sampled_aes1);

		let polyval_128: BinaryField128bPolyval =
			verifier_transcript.message().read_scalar().unwrap();
		assert_eq!(polyval_128, BinaryField128bPolyval::new(0xFFFF12345678DDDDEEEE87654321AAAA));

		let sampled_polyval_res: BinaryField128bPolyval = verifier_transcript.sample();
		assert_eq!(sampled_polyval_res, sampled_polyval1);

		verifier_transcript.finalize().unwrap();
	}

	#[test]
	fn test_advising() {
		let mut prover_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::new();
		let mut advice_writer = prover_transcript.decommitment();

		advice_writer.write_scalar(BinaryField8b::new(0x96));
		advice_writer.write_scalar(BinaryField32b::new(0xDEADBEEF));
		advice_writer.write_scalar(BinaryField128b::new(0x55669900112233550000CCDDFFEEAABB));

		advice_writer.write_scalar(AESTowerField8b::new(0x52));
		advice_writer.write_scalar(AESTowerField32b::new(0x12345678));
		advice_writer.write_scalar(AESTowerField128b::new(0xDDDDBBBBCCCCAAAA2222999911117777));

		advice_writer.write_scalar(BinaryField128bPolyval::new(0xFFFF12345678DDDDEEEE87654321AAAA));

		let mut verifier_transcript = prover_transcript.into_verifier();
		let mut advice_reader = verifier_transcript.decommitment();

		let fp_8: BinaryField8b = advice_reader.read_scalar().unwrap();
		let fp_32: BinaryField32b = advice_reader.read_scalar().unwrap();
		let fp_128: BinaryField128b = advice_reader.read_scalar().unwrap();

		assert_eq!(fp_8.val(), 0x96);
		assert_eq!(fp_32.val(), 0xDEADBEEF);
		assert_eq!(fp_128.val(), 0x55669900112233550000CCDDFFEEAABB);

		let aes_8: AESTowerField8b = advice_reader.read_scalar().unwrap();
		let aes_32: AESTowerField32b = advice_reader.read_scalar().unwrap();
		let aes_128: AESTowerField128b = advice_reader.read_scalar().unwrap();

		assert_eq!(aes_8.val(), 0x52);
		assert_eq!(aes_32.val(), 0x12345678);
		assert_eq!(aes_128.val(), 0xDDDDBBBBCCCCAAAA2222999911117777);

		let polyval_128: BinaryField128bPolyval = advice_reader.read_scalar().unwrap();
		assert_eq!(polyval_128, BinaryField128bPolyval::new(0xFFFF12345678DDDDEEEE87654321AAAA));

		verifier_transcript.finalize().unwrap();
	}

	#[test]
	fn test_challenger_and_observing() {
		let mut taped_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::new();
		let mut untaped_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::new();
		let mut challenger = HasherChallenger::<Blake2b256>::default();

		let mut rng = StdRng::seed_from_u64(0);

		const NUM_SAMPLING: usize = 32;
		let mut random_bytes = [0u8; NUM_SAMPLING * 8];
		rng.fill_bytes(&mut random_bytes);
		let mut sampled_arrays = [[0u8; 8]; NUM_SAMPLING];

		for i in 0..NUM_SAMPLING {
			taped_transcript
				.message()
				.write_scalar(BinaryField64b::new(u64::from_le_bytes(
					random_bytes[i * 8..i * 8 + 8].to_vec().try_into().unwrap(),
				)));
			untaped_transcript
				.observe()
				.write_scalar(BinaryField64b::new(u64::from_le_bytes(
					random_bytes[i * 8..i * 8 + 8].to_vec().try_into().unwrap(),
				)));
			challenger
				.observer()
				.put_slice(&random_bytes[i * 8..i * 8 + 8]);

			let sampled_out_transcript1: BinaryField64b = taped_transcript.sample();
			let sampled_out_transcript2: BinaryField64b = untaped_transcript.sample();
			let mut challenger_out = [0u8; 8];
			challenger.sampler().copy_to_slice(&mut challenger_out);
			assert_eq!(challenger_out, sampled_out_transcript1.val().to_le_bytes());
			assert_eq!(challenger_out, sampled_out_transcript2.val().to_le_bytes());
			sampled_arrays[i] = challenger_out;
		}

		let mut taped_transcript = taped_transcript.into_verifier();

		assert!(untaped_transcript.finalize().is_empty());

		for array in sampled_arrays {
			let _: BinaryField64b = taped_transcript.message().read_scalar().unwrap();
			let sampled_out_transcript: BinaryField64b = taped_transcript.sample();

			assert_eq!(array, sampled_out_transcript.val().to_le_bytes());
		}

		taped_transcript.finalize().unwrap();
	}

	#[test]
	fn test_transcript_debug() {
		let mut transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::new();

		transcript.message().write_debug("test_transcript_debug");
		transcript
			.into_verifier()
			.message()
			.read_debug("test_transcript_debug");
	}

	#[test]
	#[should_panic]
	fn test_transcript_debug_fail() {
		let mut transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::new();

		transcript.message().write_debug("test_transcript_debug");
		transcript
			.into_verifier()
			.message()
			.read_debug("test_transcript_debug_should_fail");
	}
}
