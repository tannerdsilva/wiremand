import Testing
import Foundation
import bedrock
import wiremand_databases

@Suite("WGDB domain lifecycle", .serialized)
struct WGDBDomainTests {
	@Test("domainMake issues a security key and records the subnet")
	func domainMakeIssuesKey() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		let subnet = Network("10.77.0.0/24")!
		let key = try db.domainMake(name: EncodedString("engineering"), subnet: subnet)

		let domains = try db.allDomains()
		let domain = try #require(domains.first { String($0.name) == "engineering" })
		#expect(domain.securityKey == key)
		#expect(domain.network == subnet)
	}

	@Test("domainRemove removes the domain and revokes its clients")
	func domainRemoveRevokesClients() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, name: "alice", key: WGDBFixture.clientA)

		let (removedNetwork, removedClients) = try db.domainRemove(name: EncodedString("engineering"))
		#expect(removedNetwork.cidrstring == "10.77.0.0/24")
		#expect(removedClients[WGDBFixture.clientA] == true)

		let domains = try db.allDomains()
		#expect(!domains.contains { String($0.name) == "engineering" })
		let clients = try db.allClients()
		#expect(!clients.contains { $0.publicKey == WGDBFixture.clientA })
	}

	@Test("domainRemove on a missing domain throws")
	func domainRemoveMissingDomain() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		expectThrows {
			_ = try db.domainRemove(name: EncodedString("nope"))
		}
	}
}
