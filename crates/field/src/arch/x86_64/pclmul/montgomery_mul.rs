// Copyright 2024-2025 Irreducible Inc.

/// A type that can be used in SIMD polyval field multiplication
pub trait PolyvalSimdType: Copy {
	unsafe fn shuffle_epi32<const IMM8: i32>(a: Self) -> Self;
	unsafe fn xor(a: Self, b: Self) -> Self;
	unsafe fn clmul_epi64<const IMM8: i32>(a: Self, b: Self) -> Self;
	unsafe fn srli_epi64<const IMM8: i32>(a: Self) -> Self;
	unsafe fn slli_epi64<const IMM8: i32>(a: Self) -> Self;
	unsafe fn unpacklo_epi64(a: Self, b: Self) -> Self;
}

#[inline]
pub unsafe fn simd_montgomery_multiply<T: PolyvalSimdType>(h: T, y: T) -> T {
	unsafe {
		let h0 = h;
		let h1 = T::shuffle_epi32::<0x0E>(h);
		let h2 = T::xor(h0, h1);
		let y0 = y;

		// Multiply values partitioned to 64-bit parts
		let y1 = T::shuffle_epi32::<0x0E>(y);
		let y2 = T::xor(y0, y1);
		let t0 = T::clmul_epi64::<0x00>(y0, h0);
		let t1 = T::clmul_epi64::<0x11>(y, h);
		let t2 = T::clmul_epi64::<0x00>(y2, h2);
		let t2 = T::xor(t2, T::xor(t0, t1));
		let v0 = t0;
		let v1 = T::xor(T::shuffle_epi32::<0x0E>(t0), t2);
		let v2 = T::xor(t1, T::shuffle_epi32::<0x0E>(t2));
		let v3 = T::shuffle_epi32::<0x0E>(t1);

		// Polynomial reduction
		let v2 =
			xor5(v2, v0, T::srli_epi64::<1>(v0), T::srli_epi64::<2>(v0), T::srli_epi64::<7>(v0));

		let v1 =
			xor4(v1, T::slli_epi64::<63>(v0), T::slli_epi64::<62>(v0), T::slli_epi64::<57>(v0));

		let v3 =
			xor5(v3, v1, T::srli_epi64::<1>(v1), T::srli_epi64::<2>(v1), T::srli_epi64::<7>(v1));

		let v2 =
			xor4(v2, T::slli_epi64::<63>(v1), T::slli_epi64::<62>(v1), T::slli_epi64::<57>(v1));

		T::unpacklo_epi64(v2, v3)
	}
}

#[inline(always)]
unsafe fn xor4<T: PolyvalSimdType>(e1: T, e2: T, e3: T, e4: T) -> T {
	unsafe { T::xor(T::xor(e1, e2), T::xor(e3, e4)) }
}

#[inline(always)]
unsafe fn xor5<T: PolyvalSimdType>(e1: T, e2: T, e3: T, e4: T, e5: T) -> T {
	unsafe { T::xor(e1, T::xor(T::xor(e2, e3), T::xor(e4, e5))) }
}
