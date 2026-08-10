import Foundation
import Logging
import ServiceLifecycle
import wiremand_databases

/// Renders and tears down the wiremand nftables firewall as a first-class
/// `Service`, so that the rules are installed when the daemon starts and are
/// removed when it shuts down cleanly.
///
/// Lifecycle contract (Swift ServiceLifecycle, `2.6.x`):
/// - `run()` installs the ruleset, then suspends until graceful shutdown.
/// - When the `ServiceGroup` signals graceful shutdown, `run()` deletes the
///   tables that wiremand owns and returns. Returning from `run()` is the
///   only mechanism by which a service performs its teardown in this version
///   of the library (the `Service` protocol has no `shutdown()` method).
///
/// Because the `ServiceGroup` shuts services down in reverse declaration
/// order, this service should be declared *first* in the group so that the
/// firewall is torn down *last*, after the other services have stopped
/// serving traffic.
final class FirewallService: Service {
	enum Error:Swift.Error {
		case missingFirewallFile
	}

	private let logger: Logger
	private let wgdb: WireguardDatabase
	private let firewallDB: FirewallDatabase
	private let firewallPath: String

	init(wgdb: WireguardDatabase, firewallDB: FirewallDatabase, firewallPath: String, logLevel: Logger.Level) {
		var log = Logger(label: "\(String(describing: Self.self))")
		log.logLevel = logLevel
		self.logger = log
		self.wgdb = wgdb
		self.firewallDB = firewallDB
		self.firewallPath = firewallPath
	}

	func run() async throws {
		// 1. Render the ruleset into the kernel.
		try self.render()

		// 2. Remain alive until the service group signals graceful shutdown.
		//    `gracefulShutdown()` suspends until shutdown is triggered and
		//    throws `CancellationError` if the task is cancelled instead.
		try await gracefulShutdown()

		// 3. Tear down the tables wiremand owns, then return so the group can
		//    observe a clean finish.
		self.logger.info("graceful shutdown received; tearing down firewall")
		self.teardown()
	}

	/// Builds the full firewall ruleset and pushes it into the kernel.
	///
	/// Order matters: custom user rules from the firewall file are applied
	/// first, then the managed tables/chains are (re)created. `createIPFilters`
	/// flushes and recreates the tables, so a restart never leaves a partially
	/// configured firewall from a previous run.
	private func render() throws {
		// Custom user-supplied rules (raw nft commands), applied verbatim.
		let fileContent: String
		do {
			fileContent = try String(contentsOfFile: self.firewallPath, encoding: .utf8)
			self.logger.warning("Reading \(self.firewallPath) for the custom firewall rules.")
		} catch {
			self.logger.warning("Missing firewall file. Add the \(self.firewallPath) file and run again.")
			throw Error.missingFirewallFile
		}
		let bootFirewallCommands = fileContent.components(separatedBy: .newlines)
			.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
			.filter { !$0.isEmpty }

		// Managed rules: base filter tables + chains, per-domain whitelist, and
		// same-domain isolation/trace.
		let domainIsolationCommands = FirewallExecutor.createDomainFirewall(domains: try self.wgdb.allDomains())
		let ipv4Rules = try self.firewallDB.getIPv4Rules()
		let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
		let ipv6Rules = try self.firewallDB.getIPv6Rules()
		let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
		let whitelistCommands = FirewallExecutor.createWhitelist(ipv4Rules: ipv4Whitelist, ipv6Rules: ipv6Whitelist)
		let ipFilters = FirewallExecutor.createIPFilters()

		let nftableExecutor = try NFTables()
		try nftableExecutor.run(commands: bootFirewallCommands + ipFilters + whitelistCommands + domainIsolationCommands)
		self.logger.info("firewall ruleset rendered")
	}

	/// Removes the tables that wiremand owns from the kernel.
	///
	/// `delete table` (rather than `flush table`) fully removes the tables and
	/// their chains and hooks, so nothing wiremand installed survives process
	/// exit. Only the two tables created by `createIPFilters` are deleted;
	/// custom user rules in the firewall file that target other tables are
	/// left untouched.
	private func teardown() {
		let commands = [
			"delete table ip \(FirewallExecutor.table)",
			"delete table ip6 \(FirewallExecutor.table6)",
		]
		do {
			let nftableExecutor = try NFTables()
			try nftableExecutor.run(commands: commands)
			self.logger.info("firewall tables removed")
		} catch {
			self.logger.error("failed to tear down firewall tables", metadata: ["error": "\(error)"])
		}
	}
}