#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(all(
	target_arch = "aarch64",
	target_feature = "neon",
	target_feature = "aes"
))]
mod aarch64;
