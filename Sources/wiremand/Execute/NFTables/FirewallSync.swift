import Foundation
import Logging
import wiremand_databases

/// Abstracts the in-process nftables execution so the sync logic can be unit
/// tested without a live kernel. `NFTables` conforms in production.
protocol NftCommandRunner {
	func run(commands: [String]) throws
}
extension NFTables: NftCommandRunner {}

/// Abstracts the persisted per-chain rule mirror. `FirewallDatabase` conforms in
/// production; a mock can be used in tests.
protocol ChainRuleMirrorStore {
	func getChainRuleMirror(_ chainID: String) throws -> Set<String>
	func setChainRuleMirror(_ chainID: String, rules: Set<String>) throws
}
extension FirewallDatabase: ChainRuleMirrorStore {}

/// Incrementally reconciles a single nftables chain to a desired rule set.
///
/// Instead of flushing and re-adding a whole chain on every change, the sync
/// tracks the last-applied rule set per chain (the "mirror") in
/// `FirewallDatabase` and emits only the delta:
/// - **Unchanged chain**: no nft commands at all (no-op).
/// - **Additions only** (the common case): an `add rule` per new rule, appended
///   to the chain. No flush.
/// - **Any removal**: the chain is flushed and fully re-rendered. Removals are
///   rare and, at wiremand's scale, cheap enough that a scoped re-render is the
///   right call.
///
/// Why no nft handles: handles are kernel-assigned and reassigned on every
/// flush, so a cached handle can silently target the wrong rule after any
/// reload. Getting fresh handles requires parsing `nft -a list` output, which
/// renders live counter values (e.g. `counter packets 12 bytes 900`) into rule
/// text, corrupting text-based matching for the counter-bearing isolation and
/// trace rules. Matching on our own generated rule text avoids both problems:
/// additions need no handle, and removals fall back to a scoped re-render.
struct FirewallSync {
	static func chainID(family: String, table: String, chain: String) -> String {
		return "\(family)/\(table)/\(chain)"
	}

	/// Reconciles `chain` in `table` (family `ip` or `ip6`) to `desired`, a list
	/// of full rule expressions (everything after the chain name, e.g.
	/// `ip saddr 10.0.0.0/24 tcp dport 22 accept`).
	///
	/// - Parameters:
	///   - force: when true, always flush and fully re-render the chain and
	///     refresh its mirror. Used at daemon boot to guarantee a clean slate
	///     and to self-heal any state left by an unclean prior exit.
	static func sync(
		family: String,
		table: String,
		chain: String,
		desired: [String],
		force: Bool,
		runner: NftCommandRunner,
		store: ChainRuleMirrorStore,
		logger: Logger
	) throws {
		let id = chainID(family: family, table: table, chain: chain)
		let desiredSet = Set(desired)

		if !force {
			let mirror = try store.getChainRuleMirror(id)
			if mirror == desiredSet {
				logger.debug("chain unchanged; skipping", metadata: ["chain": "\(id)"])
				return
			}

			let removals = mirror.subtracting(desiredSet)
			if removals.isEmpty {
				// Add-only fast path: append just the new rules. Order is not
				// semantically significant for the rules wiremand generates
				// (independent accepts / per-domain matches over disjoint
				// subnets), so appending is safe.
				let additions = desiredSet.subtracting(mirror).sorted()
				let cmds = additions.map { "add rule \(family) \(table) \(chain) \($0)" }
				if !cmds.isEmpty {
					try runner.run(commands: cmds)
					logger.info("incremental: added \(cmds.count) rule(s)", metadata: ["chain": "\(id)"])
				}
				try store.setChainRuleMirror(id, rules: desiredSet)
				return
			}

			logger.info("chain has removals; re-rendering", metadata: ["chain": "\(id)", "removed_count": "\(removals.count)"])
		}

		// Full re-render of this chain. `add chain` is idempotent; `flush chain`
		// clears it; then all desired rules are re-added in one atomic batch.
		var cmds = ["add chain \(family) \(table) \(chain)", "flush chain \(family) \(table) \(chain)"]
		cmds += desired.map { "add rule \(family) \(table) \(chain) \($0)" }
		try runner.run(commands: cmds)
		try store.setChainRuleMirror(id, rules: desiredSet)
		logger.info("re-rendered chain", metadata: ["chain": "\(id)", "rule_count": "\(desired.count)"])
	}
}