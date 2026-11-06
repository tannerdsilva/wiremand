import Testing
import Foundation
import bedrock
import bedrock_ip
import wiremand_databases

/// Exercises the typed-environment dialect rewrite of FirewallDatabase:
/// every transaction boundary (@MDB_transact read/write), the dup-sort rule
/// tables, the chain-rule mirror, and persistence across reopen.
@Suite("firewall database (typed-environment dialect)")
struct FirewallDatabaseTests {

	private func makeFreshBase() -> String {
		let dir = FileManager.default.temporaryDirectory
			.appendingPathComponent("wiremand-fwdb-\(UUID().uuidString)", isDirectory: true)
		return dir.path
	}

	@Test("open creates a fresh environment with empty tables")
	func freshEnvironment() throws {
		let db = try FirewallDatabase.open(at: makeFreshBase())
		#expect(try db.getChainRuleMirror("ip ip_filter forward") == [])
		#expect(try db.getIPv4Rules().isEmpty)
		#expect(try db.getIPv6Rules().isEmpty)
	}

	@Test("chain rule mirror round-trips and collapses on replace")
	func chainRuleMirrorRoundTrip() throws {
		let db = try FirewallDatabase.open(at: makeFreshBase())
		let rules: Set<String> = [
			"ip saddr 10.1.0.0/24 tcp dport 22 accept",
			"ip saddr 10.1.0.0/24 udp dport 53 accept",
		]
		try db.setChainRuleMirror("ip ip_filter forward", rules: rules)
		#expect(try db.getChainRuleMirror("ip ip_filter forward") == rules)

		let replacement: Set<String> = ["ip saddr 10.2.0.0/24 tcp dport 22 accept"]
		try db.setChainRuleMirror("ip ip_filter forward", rules: replacement)
		#expect(try db.getChainRuleMirror("ip ip_filter forward") == replacement)
	}

	@Test("v4 domain rules accumulate per-domain and delete by network")
	func v4DomainRules() throws {
		let db = try FirewallDatabase.open(at: makeFreshBase())
		let domain = wiremand_databases.NetworkV4("10.1.0.0/24")!
		let other = wiremand_databases.NetworkV4("10.2.0.0/24")!
		try db.addDomainV4Rule(domain: domain, rule: EncodedString("tcp dport 22 accept"))
		try db.addDomainV4Rule(domain: domain, rule: EncodedString("udp dport 53 accept"))
		try db.addDomainV4Rule(domain: other, rule: EncodedString("tcp dport 443 accept"))

		let all = try db.getIPv4Rules()
		#expect(all[domain] == [EncodedString("tcp dport 22 accept"), EncodedString("udp dport 53 accept")])
		#expect(all[other] == [EncodedString("tcp dport 443 accept")])

		try db.deleteDomainRules(domain: bedrock_ip.Network.v4(bedrock_ip.NetworkV4("10.1.0.0/24")!))
		let after = try db.getIPv4Rules()
		#expect(after[domain] == nil)
		#expect(after[other] != nil)
	}

	@Test("v6 domain rules round-trip")
	func v6DomainRules() throws {
		let db = try FirewallDatabase.open(at: makeFreshBase())
		let domain = wiremand_databases.NetworkV6("fd00::/64")!
		try db.addDomainV6Rule(domain: domain, rule: EncodedString("ip6 saddr fd00::/64 tcp dport 22 accept"))

		let all = try db.getIPv6Rules()
		#expect(all[domain] == [EncodedString("ip6 saddr fd00::/64 tcp dport 22 accept")])

		try db.deleteDomainRules(domain: bedrock_ip.Network.v6(bedrock_ip.NetworkV6("fd00::/64")!))
		#expect(try db.getIPv6Rules()[domain] == nil)
	}

	@Test("committed writes persist across reopen")
	func persistence() throws {
		let base = makeFreshBase()
		let db = try FirewallDatabase.open(at: base)
		try db.addDomainV4Rule(domain: wiremand_databases.NetworkV4("10.3.0.0/24")!, rule: EncodedString("tcp dport 22 accept"))
		try db.setChainRuleMirror("ip ip_filter forward", rules: ["ip saddr 10.3.0.0/24 tcp dport 22 accept"])

		let reopened = try FirewallDatabase.open(at: base)
		#expect(try reopened.getIPv4Rules()[wiremand_databases.NetworkV4("10.3.0.0/24")!] == [EncodedString("tcp dport 22 accept")])
		#expect(try reopened.getChainRuleMirror("ip ip_filter forward") == ["ip saddr 10.3.0.0/24 tcp dport 22 accept"])
	}

	@Test("deleteDB removes the environment file")
	func deleteDBRemovesEnvironment() throws {
		let base = makeFreshBase()
		_ = try FirewallDatabase.open(at: base)
		let envPath = "\(base)/firewall_db"
		#expect(FileManager.default.fileExists(atPath: envPath))
		FirewallDatabase.deleteDB(base: Path(base))
		#expect(!FileManager.default.fileExists(atPath: envPath))
	}
}
