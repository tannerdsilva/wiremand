import Testing
import Foundation
import Logging
import bedrock
import wiremand_databases

/// Records every nft command batch it is asked to run, instead of touching a kernel.
private final class MockNftRunner: NftCommandRunner {
	var executed: [[String]] = []
	func run(commands: [String]) throws {
		executed.append(commands)
	}
}

/// An in-memory per-chain rule mirror.
private final class MockMirrorStore: ChainRuleMirrorStore {
	var mirror: [String: Set<String>] = [:]
	func getChainRuleMirror(_ chainID: String) throws -> Set<String> {
		mirror[chainID] ?? []
	}
	func setChainRuleMirror(_ chainID: String, rules: Set<String>) throws {
		mirror[chainID] = rules
	}
}

@Suite("firewall command builders", .serialized)
struct FirewallCommandTests {
	@Test("createIPFilters emits the full dual-stack skeleton")
	func createIPFilters() {
		let commands = FirewallExecutor.createIPFilters()

		#expect(commands.contains("add table ip ip_filter"))
		#expect(commands.contains("add table ip6 ip6_filter"))
		#expect(commands.contains("add chain ip ip_filter forward { type filter hook forward priority filter; policy drop; }"))
		#expect(commands.contains("add chain ip6 ip6_filter forward { type filter hook forward priority filter; policy drop; }"))
		#expect(commands.contains("add rule ip ip_filter forward ct state established,related counter accept"))
		// the drop-policy forward chain must be balanced by accept rules for lo
		#expect(commands.contains("add rule ip ip_filter forward iif \"lo\" counter accept"))
		// trace chain is jumped before whitelist and isolation
		let traceIndex = commands.firstIndex(of: "add rule ip ip_filter forward jump domain_trace")
		let whitelistIndex = commands.firstIndex(of: "add rule ip ip_filter forward jump whitelist")
		let isolationIndex = commands.firstIndex(of: "add rule ip ip_filter forward jump domain_isolation")
		#expect(traceIndex != nil && whitelistIndex != nil && isolationIndex != nil)
		#expect(traceIndex! < whitelistIndex!)
		#expect(whitelistIndex! < isolationIndex!)
		// equal structure for both families
		#expect(commands.count == 22)
	}

	@Test("whitelist builders render per-network rule expressions")
	func whitelistRules() {
		let v4Network = NetworkV4("10.1.0.0/24")!
		let v4 = FirewallExecutor.desiredWhitelistIPv4Rules([
			v4Network: [EncodedString("tcp dport 22 accept"), EncodedString("udp dport 53 accept")]
		])
		#expect(v4 == [
			"ip saddr 10.1.0.0/24 tcp dport 22 accept",
			"ip saddr 10.1.0.0/24 udp dport 53 accept",
		])

		let v6Network = NetworkV6("fd00:1:2:3::/64")!
		let v6 = FirewallExecutor.desiredWhitelistIPv6Rules([
			v6Network: [EncodedString("tcp dport 22 accept")]
		])
		#expect(v6 == ["ip6 saddr fd00:1:2:3::/64 tcp dport 22 accept"])
	}

	@Test("domain isolation and trace builders only emit for their family")
	func domainIsolationAndTrace() throws {
		let (db, dir) = try WGDBFixture.makeDatabase()
		defer { WGDBFixture.cleanup(dir) }
		_ = try db.domainMake(name: EncodedString("engineering"), subnet: Network("10.77.0.0/24")!)
		// the install block (host_block) is IPv6; filter to the v4 domain under test
		let domains = try db.allDomains().filter { $0.network.isV4 }

		let v4Isolation = FirewallExecutor.desiredDomainIsolationIPv4Rules(domains)
		let v6Isolation = FirewallExecutor.desiredDomainIsolationIPv6Rules(domains)
		#expect(v4Isolation == [
			"ip saddr 10.77.0.0/24 ip daddr 10.77.0.0/24 counter log prefix \"DOMAIN_ACCEPT_V4: \" accept"
		])
		#expect(v6Isolation.isEmpty)

		let v4Trace = FirewallExecutor.desiredDomainTraceIPv4Rules(domains)
		let v6Trace = FirewallExecutor.desiredDomainTraceIPv6Rules(domains)
		#expect(v4Trace == [
			"ip saddr 10.77.0.0/24 ip daddr 10.77.0.0/24 meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv4)\""
		])
		#expect(v6Trace.isEmpty)
	}
}

@Suite("firewall incremental sync", .serialized)
struct FirewallSyncTests {
	private let logger = Logger(label: "wiremand-tests")
	private let id = "ip/ip_filter/whitelist"

	@Test("an unchanged chain produces no nft commands")
	func unchangedNoOp() throws {
		let runner = MockNftRunner()
		let store = MockMirrorStore()
		let desired = ["ip saddr 10.1.0.0/24 tcp dport 22 accept"]
		try store.setChainRuleMirror(id, rules: Set(desired))

		try FirewallSync.sync(family: "ip", table: "ip_filter", chain: "whitelist", desired: desired, force: false, runner: runner, store: store, logger: logger)

		#expect(runner.executed.isEmpty)
		#expect(store.mirror[id] == Set(desired))
	}

	@Test("additions emit only the new rules")
	func additionsOnly() throws {
		let runner = MockNftRunner()
		let store = MockMirrorStore()
		let existing = "ip saddr 10.1.0.0/24 tcp dport 22 accept"
		let added = "ip saddr 10.1.0.0/24 udp dport 53 accept"
		try store.setChainRuleMirror(id, rules: Set([existing]))

		try FirewallSync.sync(family: "ip", table: "ip_filter", chain: "whitelist", desired: [existing, added], force: false, runner: runner, store: store, logger: logger)

		#expect(runner.executed == [[
			"add rule ip ip_filter whitelist ip saddr 10.1.0.0/24 udp dport 53 accept"
		]])
		#expect(store.mirror[id] == Set([existing, added]))
	}

	@Test("any removal triggers a scoped flush and full re-render")
	func removalsReRender() throws {
		let runner = MockNftRunner()
		let store = MockMirrorStore()
		let existing = "ip saddr 10.1.0.0/24 tcp dport 22 accept"
		let removed = "ip saddr 10.1.0.0/24 udp dport 53 accept"
		try store.setChainRuleMirror(id, rules: Set([existing, removed]))

		try FirewallSync.sync(family: "ip", table: "ip_filter", chain: "whitelist", desired: [existing], force: false, runner: runner, store: store, logger: logger)

		let lastBatch = try #require(runner.executed.last)
		#expect(lastBatch == [
			"add chain ip ip_filter whitelist",
			"flush chain ip ip_filter whitelist",
			"add rule ip ip_filter whitelist ip saddr 10.1.0.0/24 tcp dport 22 accept",
		])
		#expect(store.mirror[id] == Set([existing]))
	}

	@Test("force re-renders even when the mirror already matches")
	func forceReRenders() throws {
		let runner = MockNftRunner()
		let store = MockMirrorStore()
		let desired = ["ip saddr 10.1.0.0/24 tcp dport 22 accept"]
		try store.setChainRuleMirror(id, rules: Set(desired))

		try FirewallSync.sync(family: "ip", table: "ip_filter", chain: "whitelist", desired: desired, force: true, runner: runner, store: store, logger: logger)

		let lastBatch = try #require(runner.executed.last)
		#expect(lastBatch.count == 3)
		#expect(lastBatch[0] == "add chain ip ip_filter whitelist")
		#expect(lastBatch[1] == "flush chain ip ip_filter whitelist")
	}

	@Test("chain ids are family/table/chain scoped")
	func chainIDFormat() {
		#expect(FirewallSync.chainID(family: "ip", table: "a", chain: "b") == "ip/a/b")
		#expect(FirewallSync.chainID(family: "ip6", table: "a", chain: "b") == "ip6/a/b")
	}
}
