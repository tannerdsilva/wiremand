import QuickLMDB
import Foundation
import Logging
import SystemPackage
import bedrock
import bedrock_ip

// The storage for user added NFTable firewall rules.
// The base policy for the firewall is a policy drop, so
// any rules added should include an accept as the result of the rule.
public struct FirewallDatabase: Sendable {
    enum Databases: String {
        case networkV4_firewallRule = "networkV4_firewallRule"
        case networkV6_firewallRule = "networkV6_firewallRule"
    }

    let env: Environment
    let networkV4_firewallRule: Database.DupSort<NetworkV4, EncodedString>
    let networkV6_firewallRule: Database.DupSort<NetworkV6, EncodedString>
    let log: Logger

    public init(base: Path, logLevel: Logger.Level) throws {
        var makeLogger = Logger(label: "\(String(describing: Self.self))")
        makeLogger.logLevel = logLevel
        makeLogger[metadataKey: "env_path"] = "\(base.path())"
        log = makeLogger

        let envPath = base.appendingPathComponent("firewall_db")
        let fileSize = envPath.getFileSize() + (16 * 1024 * 1024 * 1024) // current + 16GB
        env = try Environment(path: envPath.path(), flags: [.noSubDir], mapSize: Int(fileSize), maxReaders: 32, maxDBs: 2, mode: [.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])

        let someTrans = try Transaction(env: env, readOnly: false)

        networkV4_firewallRule = try Database.DupSort<NetworkV4, EncodedString>(env: env, name: Databases.networkV4_firewallRule.rawValue, flags: [.create], tx: someTrans)
        networkV6_firewallRule = try Database.DupSort<NetworkV6, EncodedString>(env: env, name: Databases.networkV6_firewallRule.rawValue, flags: [.create], tx: someTrans)

        log.trace("successfully created databases")
        try someTrans.commit()
        log.info("successfully initialized Firewall Database")
    }

    static public func deleteDB(base: Path) {
		let envPath = base.appendingPathComponent("firewall_db")
		try? FileManager.default.removeItem(at:URL(filePath: envPath.path()))
	}

	/// Adds a domain rule for IPv4 on the NFTable Firewall.
	/// - Parameters
	/// 	- domain: The IPv4 domain.
	/// 	- rule: The nft syntax compliant rule.
    public func addDomainV4Rule(domain: NetworkV4, rule: EncodedString) throws {
        let newTrans = try Transaction(env: env, readOnly: false)
        try networkV4_firewallRule.setEntry(key:domain, value: rule, flags: [], tx: newTrans)
        try newTrans.commit()
    }

    /// Adds a domain rule for IPv6 on the NFTable Firewall.
	/// - Parameters
	/// 	- domain: The IPv6 domain.
	/// 	- rule: The nft syntax compliant rule.
    public func addDomainV6Rule(domain: NetworkV6, rule: EncodedString) throws {
        let newTrans = try Transaction(env: env, readOnly: false)
        try networkV6_firewallRule.setEntry(key:domain, value: rule, flags: [], tx: newTrans)
        try newTrans.commit()
    }

    // Delete all rules for a domain.
    // - Parameters
    //      - domain: The IPv4/IPv6 domain.
    public func deleteDomainRules(domain:bedrock_ip.Network) throws {
        let newTrans = try Transaction(env: env, readOnly: false)
        switch domain {
            case .v4(let v4):
                try networkV4_firewallRule.deleteEntry(key:wiremand_databases.NetworkV4(v4), tx:newTrans)
            case .v6(let v6):
                try networkV6_firewallRule.deleteEntry(key:wiremand_databases.NetworkV6(v6), tx:newTrans)
        }
        try newTrans.commit()
    }

    /// Gets all of the IPv4 domain rules for the NFTable Firewall.
	/// - Returns
	/// 	- [NetworkV4:[EncodedString]] : A dictionary of each domain and its corresponding rules.
    public func getIPv4Rules() throws -> [NetworkV4:[EncodedString]] {
        let newTrans = try Transaction(env: env, readOnly: true)
        var result = [NetworkV4:[EncodedString]]()
        networkV4_firewallRule.cursor (tx: newTrans) { cursor in
            for (networkV4, rule) in cursor.makeIterator() {
                result[networkV4, default: []].append(rule)
            }
        }
        return result
    }

    /// Gets all of the IPv6 domain rules for the NFTable Firewall.
	/// - Returns
	/// 	- [NetworkV6:[EncodedString]] : A dictionary of each domain and its corresponding rules.
    public func getIPv6Rules() throws -> [NetworkV6:[EncodedString]] {
        let newTrans = try Transaction(env: env, readOnly: true)
        var result = [NetworkV6:[EncodedString]]()
        networkV6_firewallRule.cursor (tx: newTrans) { cursor in
            for (networkV6, rule) in cursor.makeIterator() {
                result[networkV6, default: []].append(rule)
            }
        }
        return result
    }
}