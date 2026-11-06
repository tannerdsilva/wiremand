import Testing
import Foundation
import Logging
import wiremand_databases

/// Regression coverage for replacing an existing database entry. The provisioning
/// path stores a client's rendered config keyed by public key; re-issuing a config
/// for a key that already has one must replace it, not fail with `keyExists`.
@Suite("WGDB replace existing entry")
struct WGDBReplaceTests {

	@Test("serveConfiguration replaces an existing config entry for the same key")
	func serveConfigurationReplaces() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db)

		try db.serveConfiguration(EncodedString("first-config"), forPublicKey: WGDBFixture.clientA)
		let first = try db.getConfiguration(publicKey: WGDBFixture.clientA, domainName: EncodedString("engineering"))
		#expect(String(first.configuration) == "first-config")

		// re-issuing for the same public key must overwrite the stored config
		try db.serveConfiguration(EncodedString("second-config"), forPublicKey: WGDBFixture.clientA)
		let second = try db.getConfiguration(publicKey: WGDBFixture.clientA, domainName: EncodedString("engineering"))
		#expect(String(second.configuration) == "second-config", "expected the config to be replaced, got \(String(second.configuration))")
	}
}
