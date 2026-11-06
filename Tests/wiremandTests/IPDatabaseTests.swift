import Testing
import Foundation
import QuickLMDB
import bedrock
import wiremand_databases

/// Exercises the typed-environment dialect rewrite of IPDatabase: the
/// pending/resolved/failed lifecycle, the access-key metadata, and
/// persistence across reopen — all through @MDB_transact boundaries.
@Suite("ip database (typed-environment dialect)")
struct IPDatabaseTests {

	private func makeFreshBase() -> String {
		let dir = FileManager.default.temporaryDirectory
			.appendingPathComponent("wiremand-ipdb-\(UUID().uuidString)", isDirectory: true)
		return dir.path
	}

	@Test("access key round-trips and persists across reopen")
	func accessKeyRoundTrip() throws {
		let base = makeFreshBase()
		let db = try IPDatabase.open(at: base)
		do {
			_ = try db.getIPStackKey()
			Issue.record("expected getIPStackKey to throw notFound on a fresh environment")
		} catch LMDBError.notFound {
		}
		try db.setIPStackKey("test-access-key")

		let reopened = try IPDatabase.open(at: base)
		#expect(try reopened.getIPStackKey() == EncodedString("test-access-key"))
	}

	@Test("a pending address moves through the resolving/resolved lifecycle")
	func resolveLifecycle() throws {
		let base = makeFreshBase()
		let db = try IPDatabase.open(at: base)
		try db.setIPStackKey("test-access-key")

		let address = AddressV4("10.0.0.5")!
		try db.installAddress(ipv4: address)
		#expect(try db.getNextPendingAddress() == "10.0.0.5")
		let resolving = try db.getResolveStatus(address: AddressV4("10.0.0.5")!)
		guard case .resolving = resolving else {
			Issue.record("expected .resolving, got \(resolving)")
			return
		}

		let info = IPDatabase.ResolvedIPInfo(continent: nil, country: nil, region: nil, city: nil, zip: nil, isp: EncodedString("example-isp"))
		let _ = try db.installResolved(currentAddress: EncodedString("10.0.0.5"), resolvedIPInfo: info)
		#expect(try db.getNextPendingAddress() == nil)

		let resolved = try db.getResolveStatus(address: AddressV4("10.0.0.5")!)
		guard case .resolved(let stored) = resolved else {
			Issue.record("expected .resolved, got \(resolved)")
			return
		}
		#expect(stored.isp == EncodedString("example-isp"))

		// committed state survives reopen
		let reopened = try IPDatabase.open(at: base)
		let afterReopen = try reopened.getResolveStatus(address: AddressV4("10.0.0.5")!)
		guard case .resolved(let persisted) = afterReopen else {
			Issue.record("expected .resolved after reopen, got \(afterReopen)")
			return
		}
		#expect(persisted.isp == EncodedString("example-isp"))
	}

	@Test("a failed resolution is recorded and reported")
	func failedResolve() throws {
		let base = makeFreshBase()
		let db = try IPDatabase.open(at: base)

		let address = AddressV6("fd00::5")!
		try db.installAddress(ipv6: address)
		let upcallError = NSError(domain: "ipstack", code: 500)
		try db.installFailedResolve(address: "fd00::5", error: upcallError)

		let failed = try db.getResolveStatus(address: AddressV6("fd00::5")!)
		guard case .failedResolving(let message) = failed else {
			Issue.record("expected .failedResolving, got \(failed)")
			return
		}
		#expect(message.isEmpty == false)
	}

	@Test("uninstalling a pending address removes it from the queue")
	func uninstallPendingAddress() throws {
		let base = makeFreshBase()
		let db = try IPDatabase.open(at: base)

		let address = AddressV4("10.0.0.9")!
		try db.installAddress(ipv4: address)
		#expect(try db.getNextPendingAddress() == "10.0.0.9")

		try db.uninstallPending(addressString: EncodedString("10.0.0.9"))
		#expect(try db.getNextPendingAddress() == nil)
		do {
			_ = try db.getResolveStatus(address: AddressV4("10.0.0.9")!)
			Issue.record("expected getResolveStatus to throw notFound after uninstall")
		} catch LMDBError.notFound {
		}
	}

	@Test("setupMainLoop rotates over non-empty tables")
	func setupMainLoopNonEmpty() throws {
		let db = try IPDatabase.open(at: makeFreshBase())
		try db.setIPStackKey("k")

		try db.installAddress(ipv4: AddressV4("10.0.0.10")!)
		let info = IPDatabase.ResolvedIPInfo(continent: nil, country: nil, region: nil, city: nil, zip: nil, isp: EncodedString("isp"))
		_ = try db.installResolved(currentAddress: EncodedString("10.0.0.10"), resolvedIPInfo: info)

		try db.installAddress(ipv6: AddressV6("fd00::a")!)
		try db.installFailedResolve(address: "fd00::a", error: NSError(domain: "ipstack", code: 500))

		let key = try db.setupMainLoop()
		#expect(key == "k")
	}

	@Test("deleteDB removes the environment file")
	func deleteDBRemovesEnvironment() throws {
		let base = makeFreshBase()
		_ = try IPDatabase.open(at: base)
		let envPath = "\(base)/ipdb_clientinfo"
		#expect(FileManager.default.fileExists(atPath: envPath))
		IPDatabase.deleteDB(base: Path(base))
		#expect(!FileManager.default.fileExists(atPath: envPath))
	}
}
