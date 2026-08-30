import Testing
import Foundation
import bedrock
import bedrock_ip
import wiremand_databases

@Suite("WGDB handshake processing", .serialized)
struct WGDBHandshakeTests {
	private let endpoint = bedrock_ip.Address("203.0.113.7")!

	private func client(_ db: WireguardDatabase, _ key: PublicKey) throws -> WireguardDatabase.ClientInfo? {
		try db.allClients().first { $0.publicKey == key }
	}

	@Test("first handshake stores date, endpoint, and invalidation")
	func firstHandshake() throws {
		let interval: UInt64 = 3600
		let (db, dir) = try WGDBFixture.makeDatabase(handshakeInvalidationInterval: interval)
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		let now = bedrock.Date.Seconds()
		let actions = try db.processHandshakes(
			[WGDBFixture.clientA: now],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA]
		)

		#expect(actions == [.resolveIP(endpoint)])
		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(info.lastHandshake == now)
		#expect(info.endpoint == endpoint)
		#expect(info.invalidationDate.timeIntervalSinceUnixDate() == now.timeIntervalSinceUnixDate() + interval)
	}

	@Test("a newer handshake advances the invalidation date")
	func newerHandshakeAdvancesInvalidation() throws {
		let interval: UInt64 = 3600
		let (db, dir) = try WGDBFixture.makeDatabase(handshakeInvalidationInterval: interval)
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		let t0 = bedrock.Date.Seconds()
		_ = try db.processHandshakes(
			[WGDBFixture.clientA: t0],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA]
		)
		let t1 = t0.addingTimeInterval(1000)
		let actions = try db.processHandshakes(
			[WGDBFixture.clientA: t1],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA]
		)

		#expect(actions == [.resolveIP(endpoint)])
		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(info.lastHandshake == t1)
		#expect(info.invalidationDate.timeIntervalSinceUnixDate() == t1.timeIntervalSinceUnixDate() + interval)
	}

	@Test("a repeat of the same handshake produces no actions")
	func duplicateHandshakeNoOp() throws {
		let interval: UInt64 = 3600
		let (db, dir) = try WGDBFixture.makeDatabase(handshakeInvalidationInterval: interval)
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)
		_ = try WGDBFixture.makeClient(in: db, name: "bob", key: WGDBFixture.clientB)

		let now = bedrock.Date.Seconds()
		_ = try db.processHandshakes(
			[WGDBFixture.clientA: now],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA, WGDBFixture.clientB]
		)
		// second identical report: the stored handshake is not newer, so nothing happens
		let actions = try db.processHandshakes(
			[WGDBFixture.clientA: now],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA, WGDBFixture.clientB]
		)
		#expect(actions.isEmpty)

		let info = try #require(try client(db, WGDBFixture.clientA))
		#expect(info.lastHandshake == now)
	}

	@Test("a client that stops handshaking is revoked once the invalidation passes")
	func expiredClientRevoked() throws {
		// zero invalidation interval: the client's invalidation is its handshake
		// time, so after the handshake the very next poll must revoke it
		let (db, dir) = try WGDBFixture.makeDatabase(handshakeInvalidationInterval: 0)
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		let past = bedrock.Date.Seconds() - 10
		_ = try db.processHandshakes(
			[WGDBFixture.clientA: past],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA]
		)
		_ = try db.processHandshakes(
			[:],
			endpoints: [:],
			all: [WGDBFixture.clientA]
		)

		#expect(try client(db, WGDBFixture.clientA) == nil)
	}

	@Test("a stale handshake report with an expired invalidation revokes the client")
	func staleHandshakeRevokes() throws {
		let (db, dir) = try WGDBFixture.makeDatabase(handshakeInvalidationInterval: 0)
		defer { WGDBFixture.cleanup(dir) }
		_ = try WGDBFixture.makeClient(in: db, key: WGDBFixture.clientA)

		let past = bedrock.Date.Seconds() - 10
		_ = try db.processHandshakes(
			[WGDBFixture.clientA: past],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA]
		)
		// re-reporting the exact same (not newer) handshake after invalidation
		// passed must remove the client
		_ = try db.processHandshakes(
			[WGDBFixture.clientA: past],
			endpoints: [WGDBFixture.clientA: endpoint],
			all: [WGDBFixture.clientA]
		)

		#expect(try client(db, WGDBFixture.clientA) == nil)
	}

	@Test("a peer reported by wg but unknown to the database yields a remove action")
	func unknownPeerRemoveAction() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		let now = bedrock.Date.Seconds()

		let actions = try db.processHandshakes(
			[WGDBFixture.unknownKey: now],
			endpoints: [WGDBFixture.unknownKey: endpoint],
			all: [WGDBFixture.unknownKey]
		)

		#expect(actions == [.removeClient(WGDBFixture.unknownKey)])
	}
}
