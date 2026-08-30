import Testing
import Foundation
import Logging
import RAW
import RAW_base64
import bedrock
import wiremand_databases

/// Shared fixture helpers for the wiremand LMDB test suites.
///
/// Every test gets its own `WireguardDatabase` in a unique temp directory, so
/// test instances never share LMDB state and can run in parallel.
enum WGDBFixture {
	/// decodes a base64 wireguard public key into a `PublicKey`
	private static func makeKey(_ base64: String) -> PublicKey {
		let bytes = try! RAW_base64.decode(base64)
		return PublicKey(RAW_staticbuff: bytes)
	}

	/// structurally valid curve25519 public keys (random 32-byte values)
	static let serverKey = makeKey("pmsBux+i0drIC2Mt9DsoQihfwEOEhJWdVaXKJtJcOUo=")
	static let clientA = makeKey("EGHrw5mVBdd9xnz3+Qg0xaSqnMSQOu59HyJrZttTTnM=")
	static let clientB = makeKey("GSALDqRq3isR+/h99LBcuQtDc6RDNweSxlV1XVEoDiQ=")
	/// a key that is never registered in any fixture database
	static let unknownKey = makeKey("MEoSCqSQE0inR5h5NFRy1UOjZ+Hm8vVDnFM4AMIcN2k=")

	// the production install defaults to an IPv6 ULA block with a /64 mask
	// (the shared defaultDomainMask); a v4 block here would crash install
	static let serverBlock = "fd00:f00d:cafe::/64"

	/// Creates a fresh database with the standard install metadata. Returns the
	/// database and the temp directory path so the caller can clean up.
	static func makeDatabase(
		noHandshakeInvalidationInterval: UInt64 = 3600,
		handshakeInvalidationInterval: UInt64 = 2629800
	) throws -> (WireguardDatabase, String) {
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wiremand-tests-\(UUID().uuidString)")
		try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		let base = Path(dir.path)
		let db = try WireguardDatabase(base: base, logLevel: .critical)
		try db.install(
			wg_primaryInterfaceName: EncodedString("wgtest0"),
			wg_resolvedServerPublicIPv4: AddressV4("10.0.0.1")!,
			wg_resolvedServerPublicIPv6: AddressV6("fd00::1")!,
			wg_serverPublicListenPort: EncodedUInt16(RAW_native: 29300),
			serverIPBlock: Network(serverBlock)!,
			serverBlockName: EncodedString("host_block"),
			publicKey: serverKey,
			defaultDomainMask: RAW_byte(RAW_native: 64),
			noHandshakeInvalidationInterval: EncodedTimeInterval(RAW_native: noHandshakeInvalidationInterval),
			handshakeInvalidationInterval: EncodedTimeInterval(RAW_native: handshakeInvalidationInterval)
		)
		return (db, dir.path)
	}

	/// Removes a fixture directory (and its LMDB files) after a test.
	static func cleanup(_ dir: String) {
		try? FileManager.default.removeItem(atPath: dir)
	}

	/// Creates a client in a fresh domain (reusing the domain if a previous
	/// fixture call in the same test already created it), returning the assigned
	/// address.
	static func makeClient(in db: WireguardDatabase, domain: String = "engineering", name: String = "alice", key: PublicKey = clientA) throws -> Address {
		do {
			_ = try db.domainMake(name: EncodedString(domain), subnet: Network("10.77.0.0/24")!)
		} catch {
			// domain already exists from an earlier fixture call in this test
		}
		return try db.clientMake(name: EncodedString(name), publicKey: key, domain: EncodedString(domain))
	}
}

extension WireguardDatabase.ProcessedHandshakeAction: Equatable {
	public static func == (lhs: Self, rhs: Self) -> Bool {
		switch (lhs, rhs) {
			case (.removeClient(let a), .removeClient(let b)):
				return a == b
			case (.resolveIP(let a), .resolveIP(let b)):
				return a == b
			default:
				return false
		}
	}
}

/// Asserts that the body throws without caring about the specific error type.
func expectThrows(_ body: () throws -> Void) {
	do {
		try body()
		Issue.record("expected an error to be thrown")
	} catch {
		// expected
	}
}
