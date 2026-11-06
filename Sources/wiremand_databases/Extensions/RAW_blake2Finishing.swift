import RAW
import RAW_blake2

/// disambiguates `RAW_blake2.Hasher.finish()` for fixed-width staticbuff output types.
/// rawdog exposes two same-signature `finish()` overloads: one on
/// `Hasher where outType: RAW_decodable` and one on `Hasher where outType: RAW_staticbuff`.
/// a staticbuff output type satisfies both, so a direct call is ambiguous. constraining this
/// helper to `RAW_staticbuff` hides the decodable overload (the protocol constraint does not
/// imply `RAW_decodable` to the compiler), leaving the staticbuff overload unambiguous.
internal func blake2StaticbuffFinish<H: RAW_blake2_func_impl, S: RAW_staticbuff>(_ hasher: inout RAW_blake2.Hasher<H, S>) throws -> S {
	return try hasher.finish()
}
