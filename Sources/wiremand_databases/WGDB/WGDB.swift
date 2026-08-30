import QuickLMDB
import Foundation
import RAW
import RAW_dh25519
import RAW_blake2
import bedrock_ip
import bedrock
import RAW_base64
import Logging
import class Foundation.FileManager

@RAW_staticbuff(concat:RAW_dh25519.PublicKey.self)
@MDB_comparable
public struct PublicKey:Sendable, Hashable {
	fileprivate let pk:RAW_dh25519.PublicKey
	public var string:String {
		String(RAW_base64.encode(self))
	}
}

@RAW_staticbuff(concat:bedrock_ip.AddressV4.self)
@MDB_comparable
public struct AddressV4:Sendable, Hashable, Comparable {
	fileprivate let addr:bedrock_ip.AddressV4
	public var string:String {
		String(self.addr)
	}
	public init(_ addrIn:bedrock_ip.AddressV4) {
		addr = addrIn
	}
	public init?(_ string:String) {
		let addrIn = bedrock_ip.AddressV4(string)
		guard addrIn != nil else {
			return nil
		}
		addr = addrIn!
	}
}

@RAW_staticbuff(concat:bedrock_ip.NetworkV4.self)
@MDB_comparable
public struct NetworkV4:Sendable, Hashable, Comparable {
	fileprivate let net:bedrock_ip.NetworkV4
	public var cidrstring:String {
		self.net.description
	}
	public var addressString:String {
		String(self.net.address)
	}
	public init(_ netIn:bedrock_ip.NetworkV4) {
		net = netIn
	}
	public init?(_ string:String) {
		let netIn = bedrock_ip.NetworkV4(string)
		guard netIn != nil else {
			return nil
		}
		net = netIn!
	}
}

@RAW_staticbuff(concat:bedrock_ip.AddressV6.self)
@MDB_comparable
public struct AddressV6:Sendable, Hashable, Comparable {
	fileprivate let addr:bedrock_ip.AddressV6
	public var string:String {
		String(self.addr)
	}
	public init(_ addrIn:bedrock_ip.AddressV6) {
		addr = addrIn
	}
	public init?(_ string:String) {
		let addrIn = bedrock_ip.AddressV6(string)
		guard addrIn != nil else {
			return nil
		}
		addr = addrIn!
	}
}

@RAW_staticbuff(concat:bedrock_ip.NetworkV6.self)
@MDB_comparable
public struct NetworkV6:Sendable, Hashable, Comparable {
	fileprivate let net:bedrock_ip.NetworkV6
	public var cidrstring:String {
		self.net.description
	}
	public var addressString:String {
		String(self.net.address)
	}
	public init(_ netIn:bedrock_ip.NetworkV6) {
		net = netIn
	}
	public init?(_ string:String) {
		let netIn = bedrock_ip.NetworkV6(string)
		guard netIn != nil else {
			return nil
		}
		net = netIn!
	}
}

@MDB_comparable
public struct Address:Sendable, Hashable, Comparable {
	fileprivate let addr:bedrock_ip.Address
	public var string:String {
		String(self.addr)
	}
	public var isV4:Bool {
		switch self.addr {
			case .v4(_):
				return true
			case .v6(_):
				return false
		}
	}
	public init(_ addrIn:bedrock_ip.Address) {
		addr = addrIn
	}
	public init?(_ string:String) {
		let addrIn = bedrock_ip.Address(string)
		guard addrIn != nil else {
			return nil
		}
		addr = addrIn!
	}
}

extension Address:RAW_accessible {
	public borrowing func RAW_access<R, E>(_ body:(UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E:Swift.Error {
		return try addr.RAW_access(body)
	}
	public mutating func RAW_access_mutating<R, E>(_ body:(UnsafeMutableBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E:Swift.Error {
		var addr = addr.self
		return try addr.RAW_access_mutating(body)
	}
}

extension Address:RAW_decodable {
	public init?(RAW_decode:UnsafeRawPointer, count:size_t) {
		guard let addr = bedrock_ip.Address(RAW_decode:RAW_decode, count:count) else {
			return nil
		}
		self.addr = addr
	}
}



@MDB_comparable
public struct Network:Sendable, Hashable, Comparable {
	fileprivate let net:bedrock_ip.Network
	public var cidrstring:String {
		self.net.description
	}
	public var isV4:Bool {
		switch self.net {
			case .v4(_):
				return true
			case .v6(_):
				return false
		}
	}
	public var addressString:String {
		switch self.net {
			case .v4(let v4):
				return String(v4.address)
			case .v6(let v6):
				return String(v6.address)
		}
	}
	public init(_ netIn:bedrock_ip.Network) {
		net = netIn
	}
	public init?(_ string:String) {
		let netIn = bedrock_ip.Network(string)
		guard netIn != nil else {
			return nil
		}
		net = netIn!
	}
}

extension Network:RAW_accessible {
	public borrowing func RAW_access<R, E>(_ body:(UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E:Swift.Error {
		return try net.RAW_access(body)
	}
	public mutating func RAW_access_mutating<R, E>(_ body:(UnsafeMutableBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E:Swift.Error {
		var net = self.net
		return try net.RAW_access_mutating(body)
	}
}

extension Network:RAW_decodable {
	public init?(RAW_decode:UnsafeRawPointer, count:size_t) {
		guard let net = bedrock_ip.Network(RAW_decode:RAW_decode, count:count) else {
			return nil
		}
		self.net = net
	}
}

@RAW_convertible_string_type<UTF8>(backing:RAW_byte.self)
@MDB_comparable
public struct EncodedString:Sendable, Hashable, ExpressibleByStringLiteral, Comparable {}

@RAW_staticbuff(bytes:2)
@RAW_staticbuff_fixedwidthinteger_type<UInt16>(bigEndian:true)
public struct EncodedUInt16:Sendable, ExpressibleByIntegerLiteral {}

@RAW_staticbuff(bytes:8)
@MDB_comparable
public struct DomainHash:Sendable, Comparable {
	public init(domainName:EncodedString) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(domainName)
		self = try hasher.finish()
	}
	public init?(base64String: String) {
		let rawBytes = try? RAW_base64.decode(base64String)
		guard let bytes = rawBytes, bytes.count == MemoryLayout<Self>.size else {
			return nil
		}
		self = Self(RAW_staticbuff: bytes)
	}
	public var string:String {
		String(RAW_base64.encode(self))
	}
}

@RAW_staticbuff(bytes:16)
@MDB_comparable
public struct ClientNameHash:Sendable, Hashable {
	public init(clientName:EncodedString) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(clientName)
		self = try hasher.finish()
	}
	public var string:String {
		String(RAW_base64.encode(self))
	}
}

@RAW_staticbuff(bytes: 512)
@MDB_comparable
public struct SecurityKey:Sendable, Comparable {
	public init?(base64String: String) {
		let rawBytes = try? RAW_base64.decode(base64String)
		guard let bytes = rawBytes, bytes.count == MemoryLayout<Self>.size else {
			return nil
		}
		self = Self(RAW_staticbuff: bytes)
	}
	public init?(randomBytes: [UInt8]) {
		guard randomBytes.count == MemoryLayout<Self>.size else {
			return nil
		}
		self = Self(RAW_staticbuff: randomBytes)
	}
	public var string:String {
		String(RAW_base64.encode(self))
	}
}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
public struct EncodedTimeInterval:Sendable {
	public var timeInterval: TimeInterval {
		let hostOrder = UInt64(bigEndian: self.RAW_native())
		return TimeInterval(hostOrder)
	}
	
	public init(_ timeInterval: TimeInterval) {
		self = EncodedTimeInterval(RAW_native: UInt64(round(timeInterval)))
	}
}

extension bedrock.Date.Seconds: @retroactive Hashable, @retroactive Comparable {}

enum WGDBError:Swift.Error {
	case immutableClient
	case domainNotFound
	case clientExistsInDomain
	case addressSpaceExhausted
	case invalidServerBlock
}

/// Core persistence layer for WireGuard client, domain, and handshake management.
/// - Domain Model: Domains partition the IPv6 address space. Clients inherit their domain from their assigned subnet.
/// - Invalidation: Clients are auto-removed if `invalidationDate < now`. Handshakes reset this date.
/// - Handshake Processing: Stores up to date handshake information
public struct WireguardDatabase: Sendable {
	private enum Metadatas:String {
		/// The primary interface name for the wireguard interface.
		case wg_primaryInterfaceName = "wg_primaryWGInterfaceName"			// String
		/// The public IPv4 address for the server.
		case wg_serverPublicIPv4Address = "wg_serverPublicIPv4Address"		// AddressV4?
		/// The public IPv6 address for the server.
		case wg_serverPublicIPv6Address = "wg_serverPublicIPv6Address"		// AddressV6?
		/// The public port that the wireguard process is listening on.
		case wg_serverPublicListenPort = "wg_serverPublicListenPort"		// UInt16
		/// The public key for the server.
		case wg_serverPublicKey = "serverPublicKey" //String
		/// The default invalidation interval
		case wg_noHandshakeInvalidationInterval = "noHandshakeInvalidationInterval" //TimeInterval
		case wg_handshakeInvalidationInterval = "handshakeInvalidationInterval" //TimeInterval
		case wg_database_version = "wg_database_version" //UInt64
		case wg_serverPrimarySubnet = "wg_serverPrimarySubnet"
		case wg_serverPrimarySubnetName = "wg_serverPrimarySubnetName"
	}
	public enum Databases:String {
		case metadata = "wgdb_metadata_db"

		case addressName_hostSubnet = "addrName_hostSubnet"
		// client pub and address mappings
		case clientPub_ip = "pub_ip"
		case ip_clientPub = "ip_pub"
		
		case clientPub_clientName = "pub_name"
		case clientPub_createdOn = "pub_createDate"
		case domainHash_domainName = "domainHash_domainName"
		case clientPub_domainHash = "pub_domainNameHash"
		// Maps a client public key to their respective handshake date
		case clientPub_handshakeDate = "wgdb_clientPub_handshakeDate"
		/// Maps a client public key to their respective endpoint address
		case clientPub_endpointAddress = "wgdb_clientPub_endpointAddr" 
		/// Maps a client public key to their respective invalidation date
		case clientPub_invalidDate = "wgdb_clientPub_invalidDate" 
		
		/// Maps a given domain name to its respective IPv6 network
		case domainHash_network = "wgdb_domainHash_network" 
		
		/// Maps a given domain CIDR to its respective domain name
		case networkV6_domainName = "wgdb_networkV6_domainName" 
		
		/// Maps a given domain name hash to its respective security key
		/// - not specified on domains that do not have the public api activated
		case domainHash_securityKey = "wgdb_domainHash_securityKey" 
		
		/// Maps a given domain name to the various public keys that it encompasses
		case domainHash_clientPub = "wgdb_domainHash_clientPub"
		
		/// Maps a given domain name to the various client name that reside within it. This prevents name conflicts
		case domainHash_clientNameHash = "wgdb_domainHash_clientNameHash" 

		/// Maps a ip address to a domain hash. Used to keep track of which client ip belongs to which domain.
		case ip_domainHash = "wgdb_ip_domainHash" 
		
		/// Maps a given client public key to the config data that may be served
		case webServe__clientPub_configData = "wgdb___webserve_clientPub_configData"
		
		/// Marks a client as granted access to the internal MCP admin server.
		/// Key present = access granted, absent = revoked. Cleared on full client removal.
		case clientPub_mcpAccess = "wgdb_clientPub_mcpAccess"
	}
	
	let log:Logger
	
	// basics
	let env:Environment
	let metadata:Database
			
	// - required ip related databases
	let clientPub_ip:Database.DupSort<PublicKey, Address>
	let ip_clientPub:Database.Strict<Address, PublicKey>
	
	// - required client info
	let clientPub_clientName:Database.Strict<PublicKey, EncodedString>
	let clientPub_createdOn:Database.Strict<PublicKey, bedrock.Date.Seconds>

	// - required domain info
	let domainHash_domainName:Database.Strict<DomainHash, EncodedString>
	
	// - optional metadata about the client that is captured when the client connects to the network. this is not required for the client to be considered "valid" and "functional" in the system
	let clientPub_handshakeDate:Database.Strict<PublicKey, bedrock.Date.Seconds>
	let clientPub_endpointAddress:Database.Strict<PublicKey, bedrock_ip.Address>
	
	// - if the client is configured to be auto revoked, this is the date that it will be revoked.
	// 	- note: this database is only valid for clients that have connected to the network at least once. if a client has never connected to the network, it will not have a valid entry in this database, and any auto 
	let clientPub_invalidDate:Database.Strict<PublicKey, bedrock.Date.Seconds>
	
	// domain info
	let domainHash_network:Database.Strict<DomainHash, Network>
	let network_domainHash:Database.Strict<Network, DomainHash>
	let domainHash_securityKey:Database.Strict<DomainHash, SecurityKey>
	
	// domain + client info
	let domainHash_clientPub:Database.DupSort<DomainHash, PublicKey>
	let clientPub_domainHash:Database.DupSort<PublicKey, DomainHash>
	let domainHash_clientNameHash:Database.DupSort<DomainHash, ClientNameHash>
	let ip_domainHash:Database.Strict<Address, DomainHash>
	
	let webserve__clientPub_configData:Database.Strict<PublicKey, EncodedString>
	
	// - mcp access (key presence = granted)
	let pub_mcpAccess:Database.Strict<PublicKey, RAW_byte>
	
	public func serveConfiguration(_ configString:EncodedString, forPublicKey publicKey:PublicKey) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		// confirm it exists
		_ = try clientPub_domainHash.loadEntry(key: publicKey, tx: newTrans)
		try webserve__clientPub_configData.setEntry(key: publicKey, value: configString, flags: [.noOverwrite], tx: newTrans)
		try newTrans.commit()
	}
	public func getConfiguration(publicKey:PublicKey, domainName:EncodedString) throws -> (configuration:EncodedString, name:EncodedString) {
		let newTrans = try Transaction(env: env, readOnly: true)
		let sh = try clientPub_domainHash.loadEntry(key: publicKey, tx: newTrans)
		let domainHash = try DomainHash(domainName: domainName)
		guard sh == domainHash else {
			throw LMDBError.notFound
		}
		let getName = try clientPub_clientName.loadEntry(key: publicKey, tx: newTrans)
		return (configuration:try self.webserve__clientPub_configData.loadEntry(key: publicKey, tx: newTrans), name:getName)
	}

	// MARK: - MCP access control

	/// Resolves the client public key that owns a given in-tunnel address.
	/// Used by the MCP server to authenticate a peer from its source address.
	public func clientPublicKey(forAddress address:Address) throws -> PublicKey {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try ip_clientPub.loadEntry(key: address, tx: newTrans)
	}

	/// Grants MCP admin access to the client with the given public key.
	public func grantMCPAccess(publicKey:PublicKey) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try pub_mcpAccess.setEntry(key: publicKey, value: RAW_byte(RAW_native: 1), flags: [], tx: newTrans)
		try newTrans.commit()
	}

	/// Revokes MCP admin access from the client with the given public key.
	public func revokeMCPAccess(publicKey:PublicKey) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try? pub_mcpAccess.deleteEntry(key: publicKey, tx: newTrans)
		try newTrans.commit()
	}

	/// Whether the client with the given public key currently holds MCP admin access.
	public func hasMCPAccess(publicKey:PublicKey) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		do {
			_ = try pub_mcpAccess.loadEntry(key: publicKey, tx: newTrans)
			return true
		} catch LMDBError.notFound {
			return false
		}
	}

	public init(base:Path, logLevel:Logger.Level) throws {
		var makeLogger = Logger(label:"\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		makeLogger[metadataKey:"env_path"] = "\(base.path())"
		log = makeLogger
		let envPath = base.appendingPathComponent("wgdb_clientinfo")
		let fileSize = envPath.getFileSize() + (16 * 1024 * 1024 * 1024) // current + 16GB
		env = try Environment(path:envPath.path(), flags:[.noSubDir], mapSize:Int(fileSize), maxReaders:32, maxDBs:32, mode:[.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])
		log.debug("successfully created environment", metadata:["mmap_size":"\(fileSize)b"])
		let someTrans = try Transaction(env:env, readOnly:false)
		log.trace("successfully created transaction")
		metadata = try Database(env:env, name:Databases.metadata.rawValue, flags:[.create], tx:someTrans)
		clientPub_ip = try Database.DupSort<PublicKey, Address>(env:env, name:Databases.clientPub_ip.rawValue, flags:[.create], tx:someTrans)
		ip_clientPub = try Database.Strict<Address, PublicKey>(env:env, name:Databases.ip_clientPub.rawValue, flags:[.create], tx:someTrans)
		clientPub_clientName = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.clientPub_clientName.rawValue, flags:[.create], tx:someTrans)
		clientPub_createdOn = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_createdOn.rawValue, flags:[.create], tx:someTrans)
		domainHash_domainName = try Database.Strict<DomainHash, EncodedString>(env:env, name:Databases.domainHash_domainName.rawValue, flags:[.create], tx:someTrans)
		clientPub_domainHash = try Database.DupSort<PublicKey, DomainHash>(env:env, name:Databases.clientPub_domainHash.rawValue, flags:[.create], tx:someTrans)
		clientPub_handshakeDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_handshakeDate.rawValue, flags:[.create], tx:someTrans)
		clientPub_endpointAddress = try Database.Strict<PublicKey, bedrock_ip.Address>(env:env, name:Databases.clientPub_endpointAddress.rawValue, flags:[.create], tx:someTrans)
		clientPub_invalidDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_invalidDate.rawValue, flags:[.create], tx:someTrans)
		domainHash_network = try Database.Strict<DomainHash, Network>(env:env, name:Databases.domainHash_network.rawValue, flags:[.create], tx:someTrans)
		network_domainHash = try Database.Strict<Network, DomainHash>(env:env, name:Databases.networkV6_domainName.rawValue, flags:[.create], tx:someTrans)
		domainHash_securityKey = try Database.Strict<DomainHash, SecurityKey>(env:env, name:Databases.domainHash_securityKey.rawValue, flags:[.create], tx:someTrans)
		domainHash_clientPub = try Database.DupSort<DomainHash, PublicKey>(env:env, name:Databases.domainHash_clientPub.rawValue, flags:[.create], tx:someTrans)
		domainHash_clientNameHash = try Database.DupSort<DomainHash, ClientNameHash>(env:env, name:Databases.domainHash_clientNameHash.rawValue, flags:[.create], tx:someTrans)
		ip_domainHash = try Database.Strict<Address, DomainHash>(env:env, name:Databases.ip_domainHash.rawValue, flags:[.create], tx:someTrans)
		webserve__clientPub_configData = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.webServe__clientPub_configData.rawValue, flags:[.create], tx:someTrans)
		pub_mcpAccess = try Database.Strict<PublicKey, RAW_byte>(env:env, name:Databases.clientPub_mcpAccess.rawValue, flags:[.create], tx:someTrans)
		log.trace("successfully created databases")
		try someTrans.commit()
		log.info("successfully initialized WireguardDatabase")
	}

	static public func deleteDB(base: Path) {
		let envPath = base.appendingPathComponent("wgdb_clientinfo")
		try? FileManager.default.removeItem(at:URL(filePath: envPath.path()))
	}
	
	/// The setup function for a new host. Creates new databases for the host.
	/// Adds necessary metadata values for the host to the metadata database.
	public func install(wg_primaryInterfaceName:EncodedString, wg_resolvedServerPublicIPv4:AddressV4, wg_resolvedServerPublicIPv6:AddressV6, wg_serverPublicListenPort:EncodedUInt16, serverIPBlock:Network, serverBlockName:EncodedString, publicKey:PublicKey, noHandshakeInvalidationInterval:EncodedTimeInterval = EncodedTimeInterval(RAW_native: 3600), handshakeInvalidationInterval:EncodedTimeInterval = EncodedTimeInterval(RAW_native: 2629800)) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		
		let myClientName = EncodedString("localhost")
		guard let myAddress = Address(serverIPBlock.addressString) else {
			throw WGDBError.invalidServerBlock
		}
		// the server's own domain (`host_block`) is exactly the block the
		// admin supplied; the block's own prefix is authoritative for its family
		let myDomain = serverIPBlock
		let myDomainName = serverBlockName
		let myDomainHash = try DomainHash(domainName: myDomainName)
		
		try clientPub_ip.setEntry(key:publicKey, value:myAddress, flags:[], tx:newTrans)
		try ip_clientPub.setEntry(key:myAddress, value:publicKey, flags:[], tx:newTrans)
		try clientPub_clientName.setEntry(key:publicKey, value:myClientName, flags:[], tx:newTrans)
		try clientPub_createdOn.setEntry(key:publicKey, value:bedrock.Date.Seconds(), flags:[], tx:newTrans)
		try clientPub_domainHash.setEntry(key:publicKey, value:myDomainHash, flags:[], tx:newTrans)
		
		try domainHash_network.setEntry(key:myDomainHash, value:myDomain, flags: [], tx:newTrans)
		try network_domainHash.setEntry(key:myDomain, value:myDomainHash, flags: [], tx:newTrans)

		try domainHash_securityKey.setEntry(key:myDomainHash, value:SecurityKey(randomBytes: try generateRandomBytes(count: MemoryLayout<SecurityKey>.size))!, flags:[], tx:newTrans)
		try domainHash_clientPub.setEntry(key:myDomainHash, value:publicKey, flags:[], tx:newTrans)
		try domainHash_clientNameHash.setEntry(key: myDomainHash, value: ClientNameHash(clientName: myClientName), flags: [], tx: newTrans)
		try ip_domainHash.setEntry(key: myAddress, value: myDomainHash, flags: [], tx: newTrans)
		try domainHash_domainName.setEntry(key: myDomainHash, value: myDomainName, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPrimarySubnet.rawValue), value: serverIPBlock, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPrimarySubnetName.rawValue), value: serverBlockName, flags: [], tx: newTrans)

		try metadata.setEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), value: wg_primaryInterfaceName, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv4Address.rawValue), value: wg_resolvedServerPublicIPv4, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv6Address.rawValue), value: wg_resolvedServerPublicIPv6, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), value: wg_serverPublicListenPort, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), value: publicKey, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_noHandshakeInvalidationInterval.rawValue), value: noHandshakeInvalidationInterval, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_handshakeInvalidationInterval.rawValue), value: handshakeInvalidationInterval, flags: [], tx: newTrans)
		try newTrans.commit()
	}

	/// Installs new public ipv4 and ipv6 addresses to be used for the HTTP server.
	public func installPublicIPAddresses(wg_resolvedServerPublicIPv4:AddressV4, wg_resolvedServerPublicIPv6:AddressV6) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv4Address.rawValue), value: wg_resolvedServerPublicIPv4, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv6Address.rawValue), value: wg_resolvedServerPublicIPv6, flags: [], tx: newTrans)
		try newTrans.commit()
	}

	public func primaryInterfaceName() throws -> EncodedString {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), as: EncodedString.self, tx: newTrans)!
	}
	public func getServerPublicKey(_ tx:borrowing Transaction) throws -> PublicKey {
		return try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: tx)!
	}
	public func getPublicListenPort() throws -> EncodedUInt16 {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), as: EncodedUInt16.self, tx: newTrans)!
	}
	
	public func getWireguardConfigMetas() throws -> (EncodedUInt16, Network, PublicKey, EncodedString, AddressV4, AddressV6) {
		let newTrans = try Transaction(env: env, readOnly: true)
		let getPort = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), as: EncodedUInt16.self, tx: newTrans)!
		
		let primaryServerSubnet = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPrimarySubnet.rawValue), as: Network.self, tx: newTrans)!
		let serverPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: newTrans)!
		let publicInterfaceName = try metadata.loadEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), as: EncodedString.self, tx: newTrans)!

		let publicIPv4Interface = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicIPv4Address.rawValue), as: AddressV4.self, tx: newTrans)!
		let publicIPv6Interface = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicIPv6Address.rawValue), as: AddressV6.self, tx: newTrans)!

		return (getPort, primaryServerSubnet, serverPubKey, publicInterfaceName, publicIPv4Interface, publicIPv6Interface)
	}
	
	/// Adds a domain to the hosts database.
	/// - Parameters
	/// 	- name: The domain name.
	/// 	- subnet: The network of the domain.
	public func domainMake(name:EncodedString, subnet:Network) throws -> SecurityKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: name)
		
		guard try self.network_domainHash.containsEntry(key: subnet, tx: newTrans) == false else {
			throw LMDBError.keyExists
		}
		
		// write the domain and name to the database
		try self.domainHash_network.setEntry(key: domainHash, value: subnet, flags: [.noOverwrite], tx: newTrans)
		try self.network_domainHash.setEntry(key: subnet, value: domainHash, flags: [.noOverwrite], tx: newTrans)
		
		let securityKey = SecurityKey(randomBytes: try generateRandomBytes(count: MemoryLayout<SecurityKey>.size))!
		try self.domainHash_securityKey.setEntry(key: domainHash, value: securityKey, flags: [], tx: newTrans)
		try self.domainHash_domainName.setEntry(key: domainHash, value: name, flags: [.noOverwrite], tx: newTrans)
		
		try newTrans.commit()
		return securityKey
	}
	
	/// Remove a domain and all clients associated with the domain.
	/// - Parameters
	/// 	- name: The domain name.
	/// - Returns
	/// 	- Network: The network of the removed domain.
	/// 	- [PublicKey:Bool]: A dictionary of the removed client public key and a bool indicating its revoked status.
	public func domainRemove(name:EncodedString) throws -> (Network, [PublicKey:Bool])  {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: name)
		// get the domain of this network
		let domain = try domainHash_network.loadEntry(key: domainHash, tx: newTrans)
		
		// delete the domains from the database
		try domainHash_network.deleteEntry(key:domainHash, tx:newTrans)
		try network_domainHash.deleteEntry(key:domain, tx:newTrans)
		try domainHash_securityKey.deleteEntry(key:domainHash, tx:newTrans)
		try domainHash_domainName.deleteEntry(key:domainHash, tx:newTrans)
		
		// remove any clients that may have belonged to this domain
		let clientStatus = try domainHash_clientPub.cursor(tx: newTrans) { cursor in
			var clientStatus = [PublicKey:Bool]()
			for (_, ourClientPubKey) in cursor.makeDupIterator(key: domainHash) {
				let status = try self._clientRemoveDomain(publicKey: ourClientPubKey, domain:name, tx: newTrans)
				clientStatus[ourClientPubKey] = status
			}
			return clientStatus
		}
		
		try newTrans.commit()
		return (domain, clientStatus)
	}

	public struct DomainInfo {
		public let name:EncodedString
		public let network:Network
		public let securityKey:SecurityKey
	}
	
	public func allDomains() throws -> [DomainInfo] {
		let newTrans = try Transaction(env: env, readOnly: true)
		var domains = [DomainInfo]()
				
		try domainHash_securityKey.cursor(tx: newTrans) { securityKeyCursor in
			try domainHash_network.cursor(tx: newTrans) { networkCursor in
				try domainHash_domainName.cursor(tx: newTrans) { nameCursor in
					for (hash, domainNetwork) in networkCursor.makeIterator() {
						let securityKey = try securityKeyCursor.opSet(key: hash)
						let name = try nameCursor.opSet(key: hash)
						domains.append(DomainInfo(name: name, network: domainNetwork, securityKey: securityKey))
					}
				}
			}
		}
		return domains
	}
	
	@discardableResult public func regenerateSecurityKey(domain:EncodedString) throws -> SecurityKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: domain)
		
		let existingSecurityKey = try self.domainHash_securityKey.loadEntry(key: domainHash, tx: newTrans)
		var newSecurityKey = SecurityKey(randomBytes: try generateRandomBytes(count: MemoryLayout<SecurityKey>.size))!
		while newSecurityKey == existingSecurityKey {
			newSecurityKey = SecurityKey(randomBytes: try generateRandomBytes(count: MemoryLayout<SecurityKey>.size))!
		}
		try self.domainHash_securityKey.setEntry(key: domainHash, value: newSecurityKey, flags: [], tx: newTrans)
		
		try newTrans.commit()
		return newSecurityKey
	}
	
	/// Validate the security keys for a given domain.
	/// - Parameters
	/// 	- dk: The domain hash.
	/// 	- sk: The security key to be validated.
	public func validateSecurity(dk domainHash:DomainHash, sk securityKey:SecurityKey) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		do {
			let currentSecurityKey = try self.domainHash_securityKey.loadEntry(key: domainHash, tx: newTrans)
			if (currentSecurityKey == securityKey) {
				return true
			} else {
				return false
			}
		} catch LMDBError.notFound {
			return false
		}
	}
	
	/// Returns whether the provided name exists in the database or not.
	/// - Parameters
	/// 	- name: The name of the domain.
	public func validateDomain(name:EncodedString) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		let domainHash = try DomainHash(domainName: name)
		return try self.domainHash_network.containsEntry(key: domainHash, tx: newTrans)
	}

	@discardableResult
	/// Assigns a new IP address in the target domain for the client with the
	/// given name. The name must not already be registered in the target domain.
	/// - Parameters
	/// 	- domain: The domain of the client.
	/// 	- name: The human readable name of the client.
	public func clientAssignDomain(domain:EncodedString, name:EncodedString) throws -> Address {
		// single read transaction: LMDB allows only one reader slot per thread
		let readTrans = try Transaction(env: env, readOnly: true)
		let domainHash = try DomainHash(domainName: domain)
		guard try _domainContainsName(domainHash: domainHash, clientNameHash: ClientNameHash(clientName: name), tx: readTrans) == false else {
			throw WGDBError.clientExistsInDomain
		}
		let publicKey = try _resolveClientPublicKeyAnywhere(name: name, tx: readTrans)
		return try clientAssignDomain(domain: domain, publicKey: publicKey)
	}

	@discardableResult
	/// Assigns a new IP address in the target domain for the client with the
	/// given public key. The key must be an existing client, must not already
	/// be a member of the target domain, and must not be the server's own key.
	/// - Parameters
	/// 	- domain: The domain of the client.
	/// 	- publicKey: The public key of the client.
	public func clientAssignDomain(domain:EncodedString, publicKey:PublicKey) throws -> Address {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: domain)

		let clientName = try clientPub_clientName.loadEntry(key: publicKey, tx: newTrans)
		let clientNameHash = try ClientNameHash(clientName: clientName)

		let myPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: newTrans)!
		guard myPubKey != publicKey else {
			throw WGDBError.immutableClient
		}
		guard try _domainContainsClient(domainHash: domainHash, publicKey: publicKey, tx: newTrans) == false else {
			throw WGDBError.clientExistsInDomain
		}
		guard try _domainContainsName(domainHash: domainHash, clientNameHash: clientNameHash, tx: newTrans) == false else {
			throw WGDBError.clientExistsInDomain
		}
		let domainSubnet = try domainHash_network.loadEntry(key: domainHash, tx: newTrans)

		let newIP = try _allocateAddress(in: domainSubnet, tx: newTrans)
		try self.clientPub_ip.setEntry(key:publicKey, value:newIP, flags:[], tx:newTrans)
		try self.ip_clientPub.setEntry(key:newIP, value:publicKey, flags:[.noOverwrite], tx:newTrans)
		try self.clientPub_domainHash.setEntry(key:publicKey, value:domainHash, flags:[], tx:newTrans)
		try self.domainHash_clientPub.setEntry(key:domainHash, value:publicKey, flags:[], tx:newTrans)
		try self.domainHash_clientNameHash.setEntry(key:domainHash, value: clientNameHash, flags:[], tx:newTrans)
		try self.ip_domainHash.setEntry(key: newIP, value: domainHash, flags: [.noOverwrite], tx: newTrans)

		try newTrans.commit()
		return newIP
	}

	/// Resolves a client public key by its global name (any domain). Used by
	/// the name-based add-domain path, where the client is by definition not
	/// yet a member of the target domain.
	fileprivate func _resolveClientPublicKeyAnywhere(name: EncodedString, tx: borrowing Transaction) throws -> PublicKey {
		return try clientPub_clientName.cursor(tx: tx) { cursor in
			for (publicKey, clientName) in cursor.makeIterator() {
				if clientName == name {
					return publicKey
				}
			}
			throw LMDBError.notFound
		}
	}

	/// Resolves a client public key by its global name, requiring that the
	/// name is registered in the given domain (matches the historical
	/// name-based resolution semantics of the domain membership commands).
	fileprivate func _resolveClientPublicKey(name: EncodedString, domainHash: DomainHash) throws -> PublicKey {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try clientPub_clientName.cursor(tx: newTrans) { cursor in
			return try domainHash_clientNameHash.cursor(tx: newTrans) { domainHashCursor in
				for (publicKey, clientName) in cursor.makeIterator() {
					if clientName == name {
						if try domainHashCursor.containsEntry(key: domainHash, value: ClientNameHash(clientName: clientName)) {
							return publicKey
						}
					}
				}
				throw LMDBError.notFound
			}
		}
	}

	/// Whether the given public key is a member of the given domain.
	/// Uses a DupSort cursor because the typed dup-sort wrapper does not
	/// expose a value-scoped `containsEntry` directly.
	fileprivate func _domainContainsClient(domainHash: DomainHash, publicKey: PublicKey, tx: borrowing Transaction) throws -> Bool {
		return try self.domainHash_clientPub.cursor(tx: tx) { cursor in
			for (_, memberKey) in cursor.makeDupIterator(key: domainHash) {
				if memberKey == publicKey {
					return true
				}
			}
			return false
		}
	}

	/// Whether the given client name hash is registered in the given domain.
	fileprivate func _domainContainsName(domainHash: DomainHash, clientNameHash: ClientNameHash, tx: borrowing Transaction) throws -> Bool {
		return try self.domainHash_clientNameHash.cursor(tx: tx) { cursor in
			return try cursor.containsEntry(key: domainHash, value: clientNameHash)
		}
	}

	/// Draws a random unallocated address inside a domain subnet, failing
	/// after a bounded number of attempts instead of spinning forever.
	fileprivate func _allocateAddress(in subnet: Network, tx: borrowing Transaction) throws -> Address {
		for _ in 0..<2048 {
			let candidate = Address(try subnet.net.randomAddress())
			if try self.ip_clientPub.containsEntry(key: candidate, tx: tx) == false {
				return candidate
			}
		}
		throw WGDBError.addressSpaceExhausted
	}

	/// Fileprivate version of `clientRemoveDomain` to be used in `domainRemove`.
	fileprivate func _clientRemoveDomain(publicKey:PublicKey, domain:EncodedString, tx:borrowing Transaction) throws -> Bool {
		let domainHash = try DomainHash(domainName: domain)
		let clientName = try clientPub_clientName.loadEntry(key:publicKey, tx:tx)
		let clientNameHash = try ClientNameHash(clientName: clientName)

		return try clientPub_ip.cursor(tx:tx) { cursor in 
			var count = 0
			for (_, _) in cursor.makeDupIterator(key:publicKey) { count += 1 }
			if count == 1 {
				// The client only in this domain. Revoke it and return true.
				try self._clientRemove(publicKey: publicKey, tx:tx)
				return true
			} else {
				// The client exists in other domains. Remove it from this one and return false.
				for (_, ip) in cursor.makeDupIterator(key:publicKey) {
					if try ip_domainHash.loadEntry(key:ip, tx:tx) == domainHash {
						let clientIP = ip

						try self.clientPub_ip.deleteEntry(key:publicKey, value:clientIP, tx:tx)
						try self.ip_clientPub.deleteEntry(key:clientIP, value:publicKey, tx:tx)
						try self.clientPub_domainHash.deleteEntry(key:publicKey, value:domainHash, tx:tx)
						try self.domainHash_clientPub.deleteEntry(key:domainHash, value:publicKey, tx:tx)
						try self.domainHash_clientNameHash.deleteEntry(key:domainHash, value: clientNameHash, tx:tx)
						try self.ip_domainHash.deleteEntry(key: clientIP, value: domainHash, tx: tx)

						return false
					}
				}
				throw LMDBError.notFound
			}
		}
	}

	@discardableResult
	/// Removes a client from a specified domain, identified by name.
	/// If it's the last domain they belong to, then it revokes the key.
	/// - Parameters
	/// 	- domain: The domain of the client.
	/// 	- name: The human readable name of the client.
	/// - Returns
	/// 	- Bool: The status of the client after domain removal. If true, then it was revoked.
	public func clientRemoveDomain(domain:EncodedString, name:EncodedString) throws -> (PublicKey, Bool) {
		let domainHash = try DomainHash(domainName: domain)
		let publicKey = try _resolveClientPublicKey(name: name, domainHash: domainHash)
		return try clientRemoveDomain(domain: domain, publicKey: publicKey)
	}

	@discardableResult
	/// Removes a client from a specified domain, identified by public key.
	/// If it's the last domain they belong to, then it revokes the key.
	/// - Parameters
	/// 	- domain: The domain of the client.
	/// 	- publicKey: The public key of the client.
	/// - Returns
	/// 	- Bool: The status of the client after domain removal. If true, then it was revoked.
	public func clientRemoveDomain(domain:EncodedString, publicKey:PublicKey) throws -> (PublicKey, Bool) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let myPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: newTrans)!
		guard myPubKey != publicKey else {
			throw WGDBError.immutableClient
		}
		guard try clientPub_clientName.containsEntry(key: publicKey, tx: newTrans) else {
			throw LMDBError.notFound
		}
		let domainHash = try DomainHash(domainName: domain)
		// only detach a client that is actually a member of the requested domain
		guard try _domainContainsClient(domainHash: domainHash, publicKey: publicKey, tx: newTrans) else {
			throw LMDBError.notFound
		}
		let didRevoke = try self._clientRemoveDomain(publicKey: publicKey, domain: domain, tx: newTrans)
		try newTrans.commit()
		return (publicKey, didRevoke)
	}
	
	fileprivate func _clientMake(name:EncodedString, publicKey:PublicKey, domain:EncodedString, noHandshakeInvalidation:bedrock.Date.Seconds?, tx:borrowing Transaction) throws -> Address {
		let domainHash = try DomainHash(domainName: domain)
				
		let domainSubnet = try domainHash_network.loadEntry(key: domainHash, tx: tx)

		let ipAddress = try _allocateAddress(in: domainSubnet, tx: tx)
		try self.clientPub_ip.setEntry(key:publicKey, value:ipAddress, flags:[.noOverwrite], tx:tx)
		try self.ip_clientPub.setEntry(key:ipAddress, value:publicKey, flags:[.noOverwrite], tx:tx)
		
		try self.clientPub_clientName.setEntry(key: publicKey, value: name, flags: [.noOverwrite], tx: tx)
		try self.clientPub_createdOn.setEntry(key: publicKey, value: bedrock.Date.Seconds(), flags: [.noOverwrite], tx: tx)
		try self.clientPub_domainHash.setEntry(key: publicKey, value: domainHash, flags: [.noOverwrite], tx: tx)
		try self.ip_domainHash.setEntry(key: ipAddress, value: domainHash, flags: [.noOverwrite], tx: tx)
		
		if noHandshakeInvalidation != nil {
			try self.clientPub_invalidDate.setEntry(key: publicKey, value: noHandshakeInvalidation!, flags: [.noOverwrite], tx: tx)
			log.info("new client invalidation date explicitly provided", metadata:["date":"\(noHandshakeInvalidation!.iso8601String())"])
		} else {
			let defaultInvalidation = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_noHandshakeInvalidationInterval.rawValue), as: EncodedTimeInterval.self, tx: tx)!
			let targetDate = bedrock.Date.Seconds().addingTimeInterval(defaultInvalidation.RAW_native())
			try self.clientPub_invalidDate.setEntry(key: publicKey, value: targetDate, flags: [.noOverwrite], tx: tx)
			log.info("new client invalidation date defined as a default value", metadata:["time_interval":"\(defaultInvalidation.timeInterval.description)", "target_date":"\(targetDate.iso8601String())"])
		}
		
		try self.domainHash_clientPub.setEntry(key: domainHash, value: publicKey, flags: [], tx: tx)
		try self.domainHash_clientNameHash.setEntry(key: domainHash, value: ClientNameHash(clientName: name), flags: [.noDupData], tx: tx)
		
		return ipAddress
	}
	
	/// Creates a new client with their ip addresses
	/// - Parameters
	/// 	- name: The name of the new client.
	/// 	- publicKey: The public key of the new client.
	/// 	- domain: The IPv6 domain of the client.
	/// 	- noHandshakeInvalidation: The date indicating when to delete the client if no handshakes have occured.
	/// - Returns
	/// 	- Address: The new address for the client.
	public func clientMake(name:EncodedString, publicKey:PublicKey, domain:EncodedString, noHandshakeInvalidation:bedrock.Date.Seconds? = nil) throws -> Address {
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try _clientMake(name:name, publicKey:publicKey, domain:domain, noHandshakeInvalidation:noHandshakeInvalidation, tx:newTrans)
		try newTrans.commit()
		return ret
	}
	
	@discardableResult fileprivate func _clientRemove(publicKey:PublicKey, tx:borrowing Transaction) throws -> PublicKey {
		let myPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: tx)!
		guard myPubKey != publicKey else {
			throw WGDBError.immutableClient
		}
		
		var clientDomains = [DomainHash]()
		self.clientPub_domainHash.cursor(tx:tx) { cursor in 
			for (_, clientDomain) in cursor.makeDupIterator(key: publicKey) {
				clientDomains.append(clientDomain)
			}
		}
		let clientName = try self.clientPub_clientName.loadEntry(key: publicKey, tx: tx)
		
		try clientPub_ip.cursor(tx:tx) { cursor in
			for (_, ipAddr) in cursor.makeDupIterator(key: publicKey) {
				try self.ip_clientPub.deleteEntry(key: ipAddr, tx: tx)
				try self.ip_domainHash.deleteEntry(key: ipAddr, tx: tx)
			}
		}
		try self.clientPub_ip.deleteEntry(key: publicKey, tx: tx)
		try self.clientPub_clientName.deleteEntry(key: publicKey, tx: tx)
		try self.clientPub_domainHash.deleteEntry(key: publicKey, tx: tx)
		try self.clientPub_createdOn.deleteEntry(key: publicKey, tx: tx)
		
		let didHandshake:Bool
		do {
			// handshake date may have never been written to the database
			try self.clientPub_handshakeDate.deleteEntry(key: publicKey, tx: tx)
			didHandshake = true
		} catch LMDBError.notFound {
			didHandshake = false
		}
		let didCaptureEndpoint:Bool
		do {
			// endpoint may have never been written to the database
			try self.clientPub_endpointAddress.deleteEntry(key: publicKey, tx: tx)
			didCaptureEndpoint = true
		} catch LMDBError.notFound {
			didCaptureEndpoint = false
		}
		
		try self.clientPub_invalidDate.deleteEntry(key:publicKey, tx:tx)

	// a revoked client never retains MCP access
	try? self.pub_mcpAccess.deleteEntry(key:publicKey, tx:tx)

		// Remove the public key from each of its domains
		for clientDomain in clientDomains {
			try self.domainHash_clientPub.deleteEntry(key: clientDomain, value:publicKey, tx: tx)
			try self.domainHash_clientNameHash.deleteEntry(key: clientDomain, value:ClientNameHash(clientName: clientName), tx: tx)
		}
		
		// webserve code here if needed
		
		log.debug("successfully removed client from database", metadata:["public_key": "\(publicKey.string)", "client_name": "\(String(clientName))", "client_domains": "\(clientDomains.map {$0.string}.joined(separator:", "))", "did_handshake": "\(didHandshake)", "did_have_endpoint": "\(didCaptureEndpoint)" /*"had_webserve_config": "\(hadWebserveConfig)"*/])
		return publicKey
	}
	
	/// Deletes a client from the database.
	/// - Parameters
	/// 	- publicKey: The public key of the client to remove.
	/// - Returns
	/// 	- PublicKey: The public key of the client that was removed.
	@discardableResult public func clientRemove(publicKey:PublicKey) throws -> PublicKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try self._clientRemove(publicKey:publicKey, tx:newTrans)
		try newTrans.commit()
		return ret
	}
	
	/// Deletes a client from the database.
	/// - Parameters
	/// 	- domain: The domain name that the client belongs to.
	/// 	- name: The name of the client.
	/// - Returns
	/// 	- PublicKey: The public key of the client that was removed.
	@discardableResult public func clientRemove(domain:EncodedString, name:EncodedString) throws -> PublicKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: domain)
		let ret = try clientPub_clientName.cursor(tx: newTrans) { cursor in
			return try domainHash_clientNameHash.cursor(tx: newTrans) { domainHashCursor in
				for (publicKey, clientName) in cursor.makeIterator() {
					if clientName == name {
						if try domainHashCursor.containsEntry(key: domainHash, value: ClientNameHash(clientName: clientName)) {
							try _clientRemove(publicKey: publicKey, tx: newTrans)
							return publicKey
						}
					}
				}
				throw LMDBError.notFound
			}
		}
		try newTrans.commit()
		return ret
	}
	
	public struct ClientInfo:Hashable {
		public let publicKey:PublicKey
		public let name:EncodedString
		public let domains:[EncodedString:Address]
		public let lastHandshake:bedrock.Date.Seconds?
		public let endpoint:bedrock_ip.Address?
		public let invalidationDate:bedrock.Date.Seconds
	}
	
	fileprivate func _allClients(domain:EncodedString? = nil, tx:borrowing Transaction) throws -> Set<ClientInfo> {
		var buildClients = Set<ClientInfo>()
		
		let serverPublicKey = try self.getServerPublicKey(tx)
		return try self.ip_domainHash.cursor(tx:tx) { ipDomainCursor in 
			return try self.clientPub_ip.cursor(tx:tx) { clientAddressCursor in
				return try self.clientPub_clientName.cursor(tx:tx) { clientNameCursor in
					return try self.clientPub_domainHash.cursor(tx:tx) { clientDomainCursor in
						return try self.clientPub_handshakeDate.cursor(tx:tx) { clientHandshakeCursor in
							return try self.clientPub_endpointAddress.cursor(tx:tx) { clientEndpointCursor in
								return try self.clientPub_invalidDate.cursor(tx:tx) { clientInvalidationCursor in
									if domain == nil {
										for (ourClientKey, clientName) in clientNameCursor {
											log.trace("current client selected", metadata:["name":"\(String(clientName))", "public_key":"\(ourClientKey.string)"])
											
											if serverPublicKey != ourClientKey {
												let lastHandshake:bedrock.Date.Seconds?
												do {
													lastHandshake = try clientHandshakeCursor.opSet(key: ourClientKey)
												} catch LMDBError.notFound {
													lastHandshake = nil
												}
												let endpoint:bedrock_ip.Address?
												do {
													endpoint = try clientEndpointCursor.opSet(key: ourClientKey)
												} catch LMDBError.notFound {
													endpoint = nil
												}
												let invalidationDate = try clientInvalidationCursor.opSet(key: ourClientKey)
												
												
												var domains = [EncodedString:Address]()
												for (_, clientAddress) in clientAddressCursor.makeDupIterator(key: ourClientKey) {
													let getDomain = try ipDomainCursor.opSet(key:clientAddress)
													let domainName = try self.domainHash_domainName.loadEntry(key: getDomain, tx: tx)
													domains[domainName] = clientAddress
												}
												
												buildClients.update(with:ClientInfo(publicKey:ourClientKey, name:clientName, domains:domains, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
											}
										}
										return buildClients
									} else {
										let domainHash = try DomainHash(domainName: domain!)
										let domainName = try self.domainHash_domainName.loadEntry(key: domainHash, tx: tx)
										try self.domainHash_clientPub.cursor(tx:tx) { domainHashCursor in
											for (_, clientPubKey) in domainHashCursor.makeDupIterator(key: domainHash) {
												let clientName = try clientNameCursor.opSet(key: clientPubKey)
												if serverPublicKey != clientPubKey {
													let lastHandshake:bedrock.Date.Seconds?
													do {
														lastHandshake = try clientHandshakeCursor.opSet(key: clientPubKey)
													} catch LMDBError.notFound {
														lastHandshake = nil
													}
													let endpoint:bedrock_ip.Address?
													do {
														endpoint = try clientEndpointCursor.opSet(key: clientPubKey)
													} catch LMDBError.notFound {
														endpoint = nil
													}
													let invalidationDate = try clientInvalidationCursor.opSet(key: clientPubKey)
													var domains = [EncodedString:Address]()
													for (_, clientAddress) in clientAddressCursor.makeDupIterator(key: clientPubKey) {
														if try ipDomainCursor.opSet(key:clientAddress) == domainHash {
															domains[domainName] = clientAddress
														}
													}
													
													buildClients.update(with:ClientInfo(publicKey:clientPubKey, name:clientName, domains:domains, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
												}
											}
										}
										return buildClients
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	public func allClients(domain:EncodedString? = nil) throws -> Set<ClientInfo> {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try _allClients(domain:domain, tx:newTrans)
	}
	
	/// Returns whether the provided client name can be added to the domain.
	/// - Parameters
	/// 	- domain: The name of the domain.
	/// 	- clientName: The name of the client to be validated.
	public func validateNewClientName(domain:EncodedString, clientName:EncodedString) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		let domainHash = try DomainHash(domainName: domain)
		let clientNameHash = try ClientNameHash(clientName: clientName)
		if try domainHash_network.containsEntry(key: domainHash, tx: newTrans) {
			return try domainHash_clientNameHash.cursor(tx:newTrans) { cursor in 
				if try cursor.containsEntry(key: domainHash, value: clientNameHash) {
					return false
				} else {
					return true
				}
			}
		}
		return true
	}
	
	fileprivate func _puntClientInvalidation(to newInvalidationDate:bedrock.Date.Seconds? = nil, publicKey:PublicKey, tx:borrowing Transaction) throws -> bedrock.Date.Seconds {
		// this is the new date that is to be assigned to the client
		let targetDate:bedrock.Date.Seconds
		
		if (newInvalidationDate != nil) {
			// if this date was provided by the caller, our work is done
			targetDate = newInvalidationDate!
		} else {
			// the caller did not provide a new invalidation date for this client. we need to take the configured time interval from the metadata database and add it to present time. this is will become the new invalidation date for the client
			let now = bedrock.Date.Seconds()
			let shiftTime = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_handshakeInvalidationInterval.rawValue), as: EncodedTimeInterval.self, tx: tx)!
			targetDate = now.addingTimeInterval(shiftTime.RAW_native())
		}
		
		// assign the new invalidation date to the client
		try self.clientPub_invalidDate.setEntry(key: publicKey, value: targetDate, flags: [], tx: tx)
		
		return targetDate
	}
	
	@discardableResult public func puntClientInvalidation(to newInvalidDate:bedrock.Date.Seconds? = nil, domain:EncodedString, name:EncodedString) throws -> bedrock.Date.Seconds {
		let domainHash = try DomainHash(domainName: domain)
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try self.domainHash_clientPub.cursor(tx:newTrans) { domainPubCursor in
			return try self.clientPub_clientName.cursor(tx:newTrans) { clientNameCursor in
				for (_, publicKey) in domainPubCursor.makeDupIterator(key:domainHash) {
					let clientName = try clientNameCursor.opSet(key: publicKey)
					if clientName == name {
						return try self._puntClientInvalidation(to: newInvalidDate, publicKey: publicKey, tx: newTrans)
					}
				}
				throw LMDBError.notFound
			}
		}
		try env.sync()
		try newTrans.commit()
		return ret
	}
	
	@discardableResult public func puntAllClients(domain:EncodedString, to newInvalidDate:bedrock.Date.Seconds? = nil) throws -> bedrock.Date.Seconds {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: domain)
		let ret = try self.domainHash_clientPub.cursor(tx:newTrans) { domainPubCursor in
			var puntTo:bedrock.Date.Seconds? = newInvalidDate
			for (_, publicKey) in domainPubCursor.makeDupIterator(key:domainHash) {
				puntTo = try self._puntClientInvalidation(to: newInvalidDate, publicKey: publicKey, tx: newTrans)
			}
			
			guard let didPunt = puntTo else {
				throw LMDBError.notFound
			}
			return didPunt
		}
		try env.sync()
		try newTrans.commit()
		return ret
	}
	
	@discardableResult public func puntClientInvalidation(to newInvalidDate:bedrock.Date.Seconds? = nil, publicKey:PublicKey) throws -> bedrock.Date.Seconds {
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try self._puntClientInvalidation(to: newInvalidDate, publicKey: publicKey, tx: newTrans)
		try env.sync()
		try newTrans.commit()
		return ret
	}
	
	public func clientRename(publicKey:PublicKey, name:EncodedString) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		let getCurrentName = try self.clientPub_clientName.loadEntry(key: publicKey, tx: newTrans)
		let getCurrentNetworkName = try self.clientPub_domainHash.loadEntry(key: publicKey, tx: newTrans)
		let hashedName = try ClientNameHash(clientName: getCurrentName)
		
		try self.domainHash_clientNameHash.deleteEntry(key: getCurrentNetworkName, value: hashedName, tx: newTrans)
		let newNameHash = try ClientNameHash(clientName: name)
		try self.domainHash_clientNameHash.setEntry(key: getCurrentNetworkName, value: newNameHash, flags: [], tx: newTrans)
		
		try clientPub_clientName.setEntry(key: publicKey, value: name, flags: [], tx: newTrans)
		try newTrans.commit()
	}
	
	public enum ProcessedHandshakeAction {
		case removeClient(PublicKey)
		case resolveIP(bedrock_ip.Address)
	}
	
	/// Processes all handshakes passed into the function. Moves invalidation dates accordingly.
	/// - Parameters
	/// 	- handshakes: The dictionary of the client's public key to the date the handshake occured.
	/// 	- endpoints: The dictionary of the client's public key to their endpoint address.
	/// 	- all: The complete set of client public keys.
	public func processHandshakes(_ handshakes:[PublicKey:bedrock.Date.Seconds], endpoints:[PublicKey:bedrock_ip.Address], all:Set<PublicKey>) throws -> [ProcessedHandshakeAction] {
		let newTrans = try Transaction(env: env, readOnly: false)
		var returnActions = [ProcessedHandshakeAction]()
		
		let ret = try self.clientPub_handshakeDate.cursor(tx: newTrans) { handshakeCursor in
			return try self.clientPub_invalidDate.cursor(tx: newTrans) { invalidationCursor in
				return try self.clientPub_endpointAddress.cursor(tx: newTrans) { endpointCursor in
					
					let handshakeInvalidationTimeInterval = try metadata.loadEntry(key: EncodedString(Metadatas.wg_handshakeInvalidationInterval.rawValue), as: EncodedTimeInterval.self, tx: newTrans)!
					
					var removeKeys = Set<PublicKey>()
					
					for (ourClientKey, ourClientHSTime) in handshakes {
						do {
							let invalidationDate = try invalidationCursor.opSet(key: ourClientKey)
							do {
								let existingHandshake = try handshakeCursor.opSet(key: ourClientKey)
								if existingHandshake < ourClientHSTime {
									// only update the handshake in the database if the new handshake is a date that is further in time than the existing handshake
									try handshakeCursor.setEntry(key: ourClientKey, value: ourClientHSTime, flags: [])
									try invalidationCursor.setEntry(key: ourClientKey, value: ourClientHSTime.addingTimeInterval(handshakeInvalidationTimeInterval.RAW_native()), flags: [])
									let clientEndpoint = endpoints[ourClientKey]!
									try endpointCursor.setEntry(key: ourClientKey, value: clientEndpoint, flags: [])
									returnActions.append(.resolveIP(clientEndpoint))
								} else if invalidationDate.timeIntervalSinceNow < 0 {
									// if the client has reached their invalidation period
									try _clientRemove(publicKey: ourClientKey, tx: newTrans)
								}
							} catch LMDBError.notFound {
								try handshakeCursor.setEntry(key: ourClientKey, value: ourClientHSTime, flags: [])
								try invalidationCursor.setEntry(key: ourClientKey, value: ourClientHSTime.addingTimeInterval(handshakeInvalidationTimeInterval.RAW_native()), flags: [])
								let clientEndpoint = endpoints[ourClientKey]!
								try endpointCursor.setEntry(key: ourClientKey, value: clientEndpoint, flags: [])
								returnActions.append(.resolveIP(clientEndpoint))
							}
							do {
								try webserve__clientPub_configData.deleteEntry(key: ourClientKey, tx: newTrans)
							} catch LMDBError.notFound {}
						} catch LMDBError.notFound {
							removeKeys.update(with:ourClientKey)
							returnActions.append(.removeClient(ourClientKey))
						}
					}
					
					let handshakenKeys = Set<PublicKey>(handshakes.keys)
					let nonHandshaken = all.subtracting(handshakenKeys)
					for curNonhandshakenClient in nonHandshaken {
						do {
							let invalidationDate = try invalidationCursor.opSet(key: curNonhandshakenClient)
							if invalidationDate.timeIntervalSinceNow < 0 {
								try _clientRemove(publicKey: curNonhandshakenClient, tx: newTrans)
							}
						} catch LMDBError.notFound {
							removeKeys.update(with:curNonhandshakenClient)
							returnActions.append(.removeClient(curNonhandshakenClient))
						}
					}
					return returnActions
				}
			}
		}
		try newTrans.commit()
		return ret
	}
}
