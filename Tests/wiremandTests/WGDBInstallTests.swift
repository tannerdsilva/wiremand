import Testing
import Foundation
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

	@Test("install accepts an IPv4 server block")
	func installIPv4ServerBlock() throws {
		// regression: the shared /64 defaultDomainMask forced-unwrapped a nil
		// Network for any v4 block; the block's own prefix is now authoritative
		let (db, dir) = try WGDBFixture.makeDatabase(serverBlock: "10.66.0.0/24")
		defer { WGDBFixture.cleanup(dir) }

		let domains = try db.allDomains()
		let host = try #require(domains.first { String($0.name) == "host_block" })
		#expect(host.network == Network("10.66.0.0/24")!)
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
			publicKey: WGDBFixture.serverKey
		)
		let domains = try db.allDomains()
		#expect(domains.contains { String($0.name) == "host_block" })
	}
}
