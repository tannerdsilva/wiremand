import Testing
import Foundation
import bedrock
import wiremand_databases

@Suite("WGDB client membership", .serialized)
struct WGDBClientTests {
	private func client(_ db: WireguardDatabase, _ key: PublicKey) throws -> WireguardDatabase.ClientInfo? {
		try db.allClients().first { $0.publicKey == key }
	}

	@Test("clientMake allocates an address and registers the reverse map")
	func clientMakeRegistersReverseMap() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		let address = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		#expect(try db.clientPublicKey(forAddress: address) == WGDBFixture.clientA)
		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(String(info.name) == "alice")
		#expect(info.domains[EncodedString("engineering")] == address)
	}

	@Test("address allocation is unique per client")
	func uniqueAllocation() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		let bAddress = try WGDBFixture.makeClient(in: db, name: "bob", key: WGDBFixture.clientB)

		// the reverse map must resolve bob's address to bob, proving no collision
		#expect(try db.clientPublicKey(forAddress: bAddress) == WGDBFixture.clientB)
	}

	@Test("clientAssignDomain by public key adds membership")
	func assignByPublicKey() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		let aAddress = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		_ = try db.domainMake(name: EncodedString("product"), subnet: Network("10.88.0.0/24")!)

		let assigned = try db.clientAssignDomain(domain: EncodedString("product"), publicKey: WGDBFixture.clientA)

		#expect(assigned != aAddress)
		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(info.domains.count == 2)
		#expect(info.domains[EncodedString("product")] == assigned)
	}

	@Test("duplicate assignment to the same domain throws")
	func duplicateAssignmentThrows() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		expectThrows {
			_ = try db.clientAssignDomain(domain: EncodedString("engineering"), publicKey: WGDBFixture.clientA)
		}
	}

	@Test("clientAssignDomain by name resolves a client registered in another domain")
	func assignByNameAcrossDomains() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		_ = try db.domainMake(name: EncodedString("product"), subnet: Network("10.88.0.0/24")!)

		let assigned = try db.clientAssignDomain(domain: EncodedString("product"), name: EncodedString("alice"))

		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(info.domains.count == 2)
		#expect(info.domains[EncodedString("product")] == assigned)
	}

	@Test("clientAssignDomain by an unknown name throws")
	func assignUnknownNameThrows() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try db.domainMake(name: EncodedString("product"), subnet: Network("10.88.0.0/24")!)

		expectThrows {
			_ = try db.clientAssignDomain(domain: EncodedString("product"), name: EncodedString("ghost"))
		}
	}

	@Test("clientAssignDomain by an unknown public key throws")
	func assignUnknownKeyThrows() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try db.domainMake(name: EncodedString("product"), subnet: Network("10.88.0.0/24")!)

		expectThrows {
			_ = try db.clientAssignDomain(domain: EncodedString("product"), publicKey: WGDBFixture.unknownKey)
		}
	}

	@Test("removing a client from its only domain revokes it")
	func removeLastDomainRevokes() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		let (key, revoked) = try db.clientRemoveDomain(domain: EncodedString("engineering"), publicKey: WGDBFixture.clientA)

		#expect(key == WGDBFixture.clientA)
		#expect(revoked == true)
		#expect(try client(db, WGDBFixture.clientA) == nil)
	}

	@Test("removing a client from one of several domains detaches it only")
	func removeFromMultiDomainDetaches() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		_ = try db.domainMake(name: EncodedString("product"), subnet: Network("10.88.0.0/24")!)
		_ = try db.clientAssignDomain(domain: EncodedString("product"), publicKey: WGDBFixture.clientA)

		let (_, revoked) = try db.clientRemoveDomain(domain: EncodedString("engineering"), name: EncodedString("alice"))

		#expect(revoked == false)
		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(info.domains.count == 1)
		#expect(info.domains[EncodedString("engineering")] == nil)
	}

	@Test("removing a client not in the requested domain throws")
	func removeNonMemberThrows() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		_ = try db.domainMake(name: EncodedString("product"), subnet: Network("10.88.0.0/24")!)

		expectThrows {
			_ = try db.clientRemoveDomain(domain: EncodedString("product"), publicKey: WGDBFixture.clientA)
		}
	}

	@Test("the server key cannot be removed from a domain")
	func serverKeyRemoveImmutable() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }

		expectThrows {
			_ = try db.clientRemoveDomain(domain: EncodedString("host_block"), publicKey: WGDBFixture.serverKey)
		}
	}
}
