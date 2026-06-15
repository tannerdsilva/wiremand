import QuickLMDB
import Foundation
import Logging
import SystemPackage
import bedrock
import bedrock_ip

public struct FirewallDatabase: Sendable {
    enum Databases: String {
        case clientIPv4_whitelistIPv4 = "clientIPv4_whitelistIPv4"
        case clientIPv6_whitelistIPv6 = "clientIPv6_whitelistIPv6"
    }

    let env: Environment
    let clientIPv4_whitelistIPv4: Database.DupSort<AddressV4, AddressV4>
    let clientIPv6_whitelistIPv6: Database.DupSort<AddressV6, AddressV6>
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

        clientIPv4_whitelistIPv4 = try Database.DupSort<AddressV4, AddressV4>(env: env, name: Databases.clientIPv4_whitelistIPv4.rawValue, flags: [.create], tx: someTrans)
        clientIPv6_whitelistIPv6 = try Database.DupSort<AddressV6, AddressV6>(env: env, name: Databases.clientIPv6_whitelistIPv6.rawValue, flags: [.create], tx: someTrans)

        log.trace("successfully created databases")
        try someTrans.commit()
        log.info("successfully initialized Firewall Database")
    }

    static public func deleteDB(base: Path) {
		let envPath = base.appendingPathComponent("firewall_db")
		try? FileManager.default.removeItem(at:URL(filePath: envPath.path()))
	}

	/// Whitelists an IPv4 address for a client on the NFTable Firewall.
	/// - Parameters
	/// 	- clientIP: The wireguard IPv4 address of the client.
	/// 	- whitelist: The list of IPv4 addresses to add to the clients whitelist.
    public func addWhitelistIPv4(clientIP: AddressV4, whitelist: [AddressV4]) throws {
        let newTrans = try Transaction(env: env, readOnly: false)
        for ip in whitelist {
            try clientIPv4_whitelistIPv4.setEntry(key: clientIP, value: ip, flags: [], tx: newTrans)
        }
        try newTrans.commit()
    }

	/// Removes any of the provided IPv4 addresses from the whitelist for a client.
	/// - Parameters
	/// 	- clientIP: The wireguard IPv4 address of the client.
	/// 	- whitelist: The list of IPv4 addresses to remove from the clients whitelist.
	/// - Returns
	/// 	- [AddressV4] : An array of the successfully removed IPv4 addresses.
    public func removeWhitelistIPv4(clientIP: AddressV4, whitelist: [AddressV4]) throws -> [AddressV4] {
        let newTrans = try Transaction(env: env, readOnly: false)
		var successfullyRemoved = [AddressV4]()
        for ip in whitelist {
            do {
                try clientIPv4_whitelistIPv4.deleteEntry(key: clientIP, value: ip, tx: newTrans)
				successfullyRemoved.append(ip)
            } catch LMDBError.notFound {
                continue
            }
        }
        try newTrans.commit()
		return successfullyRemoved
    }

	/// Whitelists an IPv6 address for a client on the NFTable Firewall.
	/// - Parameters
	/// 	- clientIP: The wireguard IPv6 address of the client.
	/// 	- whitelist: The list of IPv6 addresses to add to the clients whitelist.
    public func addWhitelistIPv6(clientIP: AddressV6, whitelist: [AddressV6]) throws {
        let newTrans = try Transaction(env: env, readOnly: false)
        for ip in whitelist {
            try clientIPv6_whitelistIPv6.setEntry(key: clientIP, value: ip, flags: [], tx: newTrans)
        }
        try newTrans.commit()
    }

	/// Removes any of the provided IPv6 addresses from the whitelist for a client.
	/// - Parameters
	/// 	- clientIP: The wireguard IPv6 address of the client.
	/// 	- whitelist: The list of IPv6 addresses to remove from the clients whitelist.
	/// - Returns
	/// 	- [AddressV6] : An array of the successfully removed IPv6 addresses.
    public func removeWhitelistIPv6(clientIP: AddressV6, whitelist: [AddressV6]) throws -> [AddressV6] {
        let newTrans = try Transaction(env: env, readOnly: false)
		var successfullyRemoved = [AddressV6]()
        for ip in whitelist {
            do {
                try clientIPv6_whitelistIPv6.deleteEntry(key: clientIP, value: ip, tx: newTrans)
				successfullyRemoved.append(ip)
            } catch LMDBError.notFound {
                continue
            }
        }
        try newTrans.commit()
		return successfullyRemoved
    }

	public func getAllWhitelistedIPv4() throws -> [AddressV4: [AddressV4]] {
        let newTrans = try Transaction(env: env, readOnly: true)
        var result: [AddressV4: [AddressV4]] = [:]

        clientIPv4_whitelistIPv4.cursor(tx: newTrans) { cursor in
            for (clientIP, whitelistIP) in cursor.makeIterator() {
                result[clientIP, default: []].append(whitelistIP)
            }
        }

        return result
    }

    public func getAllWhitelistedIPv6() throws -> [AddressV6: [AddressV6]] {
        let newTrans = try Transaction(env: env, readOnly: true)
        var result: [AddressV6: [AddressV6]] = [:]

        clientIPv6_whitelistIPv6.cursor(tx: newTrans) { cursor in
            for (clientIP, whitelistIP) in cursor.makeIterator() {
                result[clientIP, default: []].append(whitelistIP)
            }
        }

        return result
    }

    /// Removes any trace of the client on the NFTable Firewall.
	/// - Parameters
	/// 	- client: The wireguard client.
    public func removeClient(client: WireguardDatabase.ClientInfo) throws {
        let newTrans = try Transaction(env: env, readOnly: false)
        do {
            if let ipv4 = client.addressV4 {
                try clientIPv4_whitelistIPv4.deleteEntry(key: ipv4, tx: newTrans)
            }
        } catch LMDBError.notFound {}
        for ipv6 in client.address {
            do {
                try clientIPv6_whitelistIPv6.deleteEntry(key: ipv6, tx: newTrans)
            } catch LMDBError.notFound {}
        }
        try newTrans.commit()
    }
}