import RAW

/// rawdog's `generateSecureRandomBytes(count:)` is capped at 256 bytes per call.
/// some wiremand types are wider than that (the 512-byte domain security key), so a
/// request above the cap is satisfied by concatenating secure chunks.
internal func generateRandomBytesChunked(count: Int) throws -> [UInt8] {
	var output = [UInt8]()
	output.reserveCapacity(count)
	while output.count < count {
		let chunkCount = Swift.min(256, count - output.count)
		output.append(contentsOf: try generateSecureRandomBytes(count: chunkCount))
	}
	return output
}
