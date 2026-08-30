import Testing
import Foundation
import bedrock
import wiremand_databases

@Suite("WGDB MCP access control", .serialized)
struct WGDBMCPAccessTests {
	@Test("grant then revoke toggles the access bit")
	func grantRevokeToggle() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		#expect(try db.hasMCPAccess(publicKey: WGDBFixture.clientA) == false)
		try db.grantMCPAccess(publicKey: WGDBFixture.clientA)
		#expect(try db.hasMCPAccess(publicKey: WGDBFixture.clientA) == true)
		try db.revokeMCPAccess(publicKey: WGDBFixture.clientA)
		#expect(try db.hasMCPAccess(publicKey: WGDBFixture.clientA) == false)
	}

	@Test("granting to a key that was never revoked is idempotent")
	func repeatedGrantIdempotent() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		try db.grantMCPAccess(publicKey: WGDBFixture.clientA)
		try db.grantMCPAccess(publicKey: WGDBFixture.clientA)
		#expect(try db.hasMCPAccess(publicKey: WGDBFixture.clientA) == true)
	}

	@Test("clientPublicKey resolves an assigned tunnel address")
	func resolveTunnelAddress() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		let address = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		#expect(try db.clientPublicKey(forAddress: address) == WGDBFixture.clientA)
	}

	@Test("clientPublicKey throws for an unassigned address")
	func resolveUnknownAddressThrows() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		expectThrows {
			_ = try db.clientPublicKey(forAddress: Address("10.1.2.3")!)
		}
	}

	@Test("revoking a client clears its MCP grant")
	func revokedClientLosesGrant() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		try db.grantMCPAccess(publicKey: WGDBFixture.clientA)
		#expect(try db.hasMCPAccess(publicKey: WGDBFixture.clientA) == true)

		_ = try db.clientRemoveDomain(domain: EncodedString("engineering"), publicKey: WGDBFixture.clientA)

		#expect(try db.hasMCPAccess(publicKey: WGDBFixture.clientA) == false)
	}
}
