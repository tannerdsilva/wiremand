import Testing
import Foundation
import RAW
import bedrock
import wiremand_databases

@Suite("WGDB install", .serialized)
struct WGDBInstallTests {
	@Test("install creates the host block domain with the server key")
	func installHostBlock() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }

		let domains = try db.allDomains()
		#expect(domains.contains { String($0.name) == "host_block" })
	}

	@Test("the server's own key is immutable against domain assignment")
	func serverKeyImmutable() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try db.domainMake(name: EncodedString("engineering"), subnet: Network("10.77.0.0/24")!)

		expectThrows {
			_ = try db.clientAssignDomain(domain: EncodedString("engineering"), publicKey: WGDBFixture.serverKey)
		}
	}

	@Test("install is repeatable on an already-initialized database")
	func reinstall() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		// re-running install with the same parameters must not throw or corrupt
		try db.install(
			wg_primaryInterfaceName: EncodedString("wgtest0"),
			wg_resolvedServerPublicIPv4: AddressV4("10.0.0.1")!,
			wg_resolvedServerPublicIPv6: AddressV6("fd00::1")!,
			wg_serverPublicListenPort: EncodedUInt16(RAW_native: 29300),
			serverIPBlock: Network(WGDBFixture.serverBlock)!,
			serverBlockName: EncodedString("host_block"),
			publicKey: WGDBFixture.serverKey,
			defaultDomainMask: RAW_byte(RAW_native: 64)
		)
		let domains = try db.allDomains()
		#expect(domains.contains { String($0.name) == "host_block" })
	}
}
