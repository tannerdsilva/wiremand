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

@RAW_convertible_string_type<UTF8>(backing:RAW_byte.self)
@MDB_comparable
public struct EncodedString:Sendable, Hashable {}

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
public struct ClientNameHash:Sendable {
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
}

public struct WireguardDatabase: Sendable {
	private enum Metadatas:String {
		/// The primary interface name for the wireguard interface.
		case wg_primaryInterfaceName = "wg_primaryWGInterfaceName"			// String
		/// The public DNS name for the server.
		case wg_serverPublicDomainName = "wg_serverPublicDomainName"		// String
		/// The public IPv4 address for the server.
		case wg_serverPublicIPv4Address = "wg_serverPublicIPv4Address"		// AddressV4?
		/// The public IPv6 address for the server.
		case wg_serverPublicIPv6Address = "wg_serverPublicIPv6Address"		// AddressV6?
		/// The public port that the wireguard process is listening on.
		case wg_serverPublicListenPort = "wg_serverPublicListenPort"		// UInt16
		/// The complete internal scope of the server's IPv4 address space. This is the complete address space that the server can assign to clients.
		case wg_serverIPv4Block = "wg_serverIPv4Subnet" //NetworkV4 where address == servers own internal IP
		/// The public key for the server.
		case wg_serverPublicKey = "serverPublicKey" //String
		/// The default domain subnet mask for the server.
		///  - TODO: This really needs to be deleted and replaced with two different values for IPv4 and IPv6.
		case wg_defaultDomainMask = "defaultDomainMask" //UInt8
		/// The default invalidation interval
		case wg_noHandshakeInvalidationInterval = "noHandshakeInvalidationInterval" //TimeInterval
		case wg_handshakeInvalidationInterval = "handshakeInvalidationInterval" //TimeInterval
		case wg_database_version = "wg_database_version" //UInt64
	}
	public enum Databases:String {
		case metadata = "wgdb_metadata_db"

		case addressName_hostSubnet = "addrName_hostSubnet"
		// client pub and address mappings
		case clientPub_ipv4 = "pub_4"
		case ipv4_clientPub = "4_pub"
		case clientPub_ipv6 = "pub_6"
		case ipv6_clientPub = "6_pub"
		
		case clientPub_clientName = "pub_name"
		case clientPub_createdOn = "pub_createDate"
		case domainHash_domainName = "domainHash_domainName"
		case clientPub_domainHash = "pub_domainNameHash"
		// Maps a client public key to their respective handshake date
		case clientPub_handshakeDate = "wgdb_clientPub_handshakeDate" //String:Date? (optional value)
		/// Maps a client public key to their respective endpoint address
		case clientPub_endpointAddress = "wgdb_clientPub_endpointAddr" //String:String? (optional value)
		/// Maps a client public key to their respective invalidation date
		case clientPub_invalidDate = "wgdb_clientPub_invalidDate" //String:Date (non-optional but not specified for the servers own public key since the server cannot invalidate itself)
		
		/// Maps a given domain name to its respective IPv6 network
		case domainHash_networkV6 = "wgdb_domainHash_networkV6" //String:NetworkV6
		
		/// Maps a given domain CIDR to its respective domain name
		case networkV6_domainName = "wgdb_networkV6_domainName" //NetworkV6:String
		
		/// Maps a given domain name hash to its respective security key
		/// - not specified on domains that do not have the public api activated
		case domainHash_securityKey = "wgdb_domainHash_securityKey" //String:String
		
		/// Maps a given domain name to the various public keys that it encompasses
		case domainHash_clientPub = "wgdb_domainHash_clientPub" //String:String
		
		/// Maps a given domain name to the various client name that reside within it. This prevents name conflicts
		case domainHash_clientNameHash = "wgdb_domainHash_clientNameHash" //String:Data
		
		/// Maps a given client public key to the config data that may be served
		case webServe__clientPub_configData = "wgdb___webserve_clientPub_configData" //String:String
	}
	
	let log:Logger
	
	// basics
	let env:Environment
	let metadata:Database
	
	let addressName_hostSubnet:Database.Strict<EncodedString, NetworkV6>
	
	// client info ---------------------------
	// - optional ipv4 related databases
	let clientPub_ipv4:Database.Strict<PublicKey, AddressV4>
	let ipv4_clientPub:Database.Strict<AddressV4, PublicKey>
	
	// - required ipv6 related databases
	let clientPub_ipv6:Database.DupSort<PublicKey, AddressV6>
	let ipv6_clientPub:Database.Strict<AddressV6, PublicKey>
	
	// - required client info
	let clientPub_clientName:Database.Strict<PublicKey, EncodedString>
	let clientPub_createdOn:Database.Strict<PublicKey, bedrock.Date.Seconds>

	// - required domain info
	let domainHash_domainName:Database.Strict<DomainHash, EncodedString>
	
	// - optional metadata about the client that is captured when the client connects to the network. this is not required for the client to be considered "valid" and "functional" in the system
	let clientPub_handshakeDate:Database.Strict<PublicKey, bedrock.Date.Seconds>
	let clientPub_endpointAddress:Database.Strict<PublicKey, Address>
	
	// - if the client is configured to be auto revoked, this is the date that it will be revoked.
	// 	- note: this database is only valid for clients that have connected to the network at least once. if a client has never connected to the network, it will not have a valid entry in this database, and any auto 
	let clientPub_invalidDate:Database.Strict<PublicKey, bedrock.Date.Seconds>
	
	// domain info
	let domainHash_networkV6:Database.Strict<DomainHash, NetworkV6>
	let networkV6_domainHash:Database.Strict<NetworkV6, DomainHash>
	let domainHash_securityKey:Database.Strict<DomainHash, SecurityKey>
	
	// domain + client info
	let domainHash_clientPub:Database.DupSort<DomainHash, PublicKey>
	let clientPub_domainHash:Database.Strict<PublicKey, DomainHash>
	let domainHash_clientNameHash:Database.DupSort<DomainHash, ClientNameHash>
	
	let webserve__clientPub_configData:Database.Strict<PublicKey, EncodedString>
	
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
		addressName_hostSubnet = try Database.Strict<EncodedString, NetworkV6>(env:env, name:Databases.addressName_hostSubnet.rawValue, flags:[.create], tx:someTrans)
		clientPub_ipv4 = try Database.Strict<PublicKey, AddressV4>(env:env, name:Databases.clientPub_ipv4.rawValue, flags:[.create], tx:someTrans)
		ipv4_clientPub = try Database.Strict<AddressV4, PublicKey>(env:env, name:Databases.ipv4_clientPub.rawValue, flags:[.create], tx:someTrans)
		clientPub_ipv6 = try Database.DupSort<PublicKey, AddressV6>(env:env, name:Databases.clientPub_ipv6.rawValue, flags:[.create], tx:someTrans)
		ipv6_clientPub = try Database.Strict<AddressV6, PublicKey>(env:env, name:Databases.ipv6_clientPub.rawValue, flags:[.create], tx:someTrans)
		clientPub_clientName = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.clientPub_clientName.rawValue, flags:[.create], tx:someTrans)
		clientPub_createdOn = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_createdOn.rawValue, flags:[.create], tx:someTrans)
		domainHash_domainName = try Database.Strict<DomainHash, EncodedString>(env:env, name:Databases.domainHash_domainName.rawValue, flags:[.create], tx:someTrans)
		clientPub_domainHash = try Database.Strict<PublicKey, DomainHash>(env:env, name:Databases.clientPub_domainHash.rawValue, flags:[.create], tx:someTrans)
		clientPub_handshakeDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_handshakeDate.rawValue, flags:[.create], tx:someTrans)
		clientPub_endpointAddress = try Database.Strict<PublicKey, Address>(env:env, name:Databases.clientPub_endpointAddress.rawValue, flags:[.create], tx:someTrans)
		clientPub_invalidDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_invalidDate.rawValue, flags:[.create], tx:someTrans)
		domainHash_networkV6 = try Database.Strict<DomainHash, NetworkV6>(env:env, name:Databases.domainHash_networkV6.rawValue, flags:[.create], tx:someTrans)
		networkV6_domainHash = try Database.Strict<NetworkV6, DomainHash>(env:env, name:Databases.networkV6_domainName.rawValue, flags:[.create], tx:someTrans)
		domainHash_securityKey = try Database.Strict<DomainHash, SecurityKey>(env:env, name:Databases.domainHash_securityKey.rawValue, flags:[.create], tx:someTrans)
		domainHash_clientPub = try Database.DupSort<DomainHash, PublicKey>(env:env, name:Databases.domainHash_clientPub.rawValue, flags:[.create], tx:someTrans)
		domainHash_clientNameHash = try Database.DupSort<DomainHash, ClientNameHash>(env:env, name:Databases.domainHash_clientNameHash.rawValue,	 flags:[.create], tx:someTrans)
		webserve__clientPub_configData = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.webServe__clientPub_configData.rawValue, flags:[.create], tx:someTrans)
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
	public func install(wg_primaryInterfaceName:EncodedString, wg_serverPublicDomainName:EncodedString, wg_resolvedServerPublicIPv4:AddressV4, wg_resolvedServerPublicIPv6:AddressV6, wg_serverPublicListenPort:EncodedUInt16, serverIPv6Block:NetworkV6, serverIPv6BlockName:EncodedString, serverIPv4Block:NetworkV4, publicKey:PublicKey, defaultDomainMask:RAW_byte, noHandshakeInvalidationInterval:EncodedTimeInterval = EncodedTimeInterval(RAW_native: 3600), handshakeInvalidationInterval:EncodedTimeInterval = EncodedTimeInterval(RAW_native: 2629800)) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		
		let myClientName = EncodedString("localhost")
		let myAddress = AddressV6(serverIPv6Block.net.address)
		let myDomain = NetworkV6(myAddress.string + "/\(defaultDomainMask.RAW_native())")!
		let myDomainName = wg_serverPublicDomainName
		let myDomainHash = try DomainHash(domainName: myDomainName)
		
		let myIPv4 = AddressV4(serverIPv4Block.net.address)
		
		try clientPub_ipv4.setEntry(key:publicKey, value:myIPv4, flags:[], tx:newTrans)
		try ipv4_clientPub.setEntry(key:myIPv4, value:publicKey, flags:[], tx:newTrans)
		try clientPub_ipv6.setEntry(key:publicKey, value:myAddress, flags:[], tx:newTrans)
		try ipv6_clientPub.setEntry(key:myAddress, value:publicKey, flags:[], tx:newTrans)
		try clientPub_clientName.setEntry(key:publicKey, value:myClientName, flags:[], tx:newTrans)
		try clientPub_createdOn.setEntry(key:publicKey, value:bedrock.Date.Seconds(), flags:[], tx:newTrans)
		try clientPub_domainHash.setEntry(key:publicKey, value:myDomainHash, flags:[], tx:newTrans)
		
		try domainHash_networkV6.setEntry(key:myDomainHash, value:myDomain, flags: [], tx:newTrans)
		try networkV6_domainHash.setEntry(key:myDomain, value:myDomainHash, flags: [], tx:newTrans)

		try domainHash_securityKey.setEntry(key:myDomainHash, value:SecurityKey(randomBytes: try generateRandomBytes(count: MemoryLayout<SecurityKey>.size))!, flags:[], tx:newTrans)
		try domainHash_clientPub.setEntry(key:myDomainHash, value:publicKey, flags:[], tx:newTrans)
		try domainHash_clientNameHash.setEntry(key: myDomainHash, value: ClientNameHash(clientName: myClientName), flags: [], tx: newTrans)
		try domainHash_domainName.setEntry(key: myDomainHash, value: myDomainName, flags: [], tx: newTrans)
		
		try addressName_hostSubnet.setEntry(key: serverIPv6BlockName, value: serverIPv6Block, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), value: wg_primaryInterfaceName, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicDomainName.rawValue), value: wg_serverPublicDomainName, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv4Address.rawValue), value: wg_resolvedServerPublicIPv4, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv6Address.rawValue), value: wg_resolvedServerPublicIPv6, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), value: wg_serverPublicListenPort, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverIPv4Block.rawValue), value: serverIPv4Block, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), value: publicKey, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_defaultDomainMask.rawValue), value: defaultDomainMask, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_noHandshakeInvalidationInterval.rawValue), value: noHandshakeInvalidationInterval, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_handshakeInvalidationInterval.rawValue), value: handshakeInvalidationInterval, flags: [], tx: newTrans)
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
	
	public func getWireguardConfigMetas() throws -> (EncodedString, EncodedUInt16, [NetworkV6], AddressV4, PublicKey, EncodedString, AddressV4?) {
		let newTrans = try Transaction(env: env, readOnly: true)
		let getDNSName = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicDomainName.rawValue), as: EncodedString.self, tx: newTrans)!
		let getPort = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), as: EncodedUInt16.self, tx: newTrans)!
		
		var ipv6Subnets = [NetworkV6]()
		addressName_hostSubnet.cursor(tx:newTrans) { cursor in
			for (_, host) in cursor.makeIterator() {
				ipv6Subnets.append(host)
			}
		}
		let ipv4Address = AddressV4(try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverIPv4Block.rawValue), as: NetworkV4.self, tx: newTrans)!.net.address)
		let serverPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: newTrans)!
		let publicInterfaceName = try metadata.loadEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), as: EncodedString.self, tx: newTrans)!
		let publicIPv4Interface:AddressV4?
		do {
			publicIPv4Interface = try metadata.loadEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), as: AddressV4.self, tx: newTrans)
		} catch LMDBError.notFound {
			publicIPv4Interface = nil
		}
		return (getDNSName, getPort, ipv6Subnets, ipv4Address, serverPubKey, publicInterfaceName, publicIPv4Interface)
	}
	
	/// Adds a new IPv6 network for the host to the database.
	/// - Parameters
	/// 	- name: The new network name.
	/// 	- network: The network to be added.
	public func addNetwork(name:EncodedString, network:NetworkV6) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try addressName_hostSubnet.setEntry(key: name, value: network, flags: [.noOverwrite], tx: newTrans)
		try newTrans.commit()
	}
	
	/// Adds a domain to the hosts database.
	/// A domain is a soft-concept used for peer categorization. The domain of a peer is indicated by the
	/// middle X bytes of the peers IP address where `X = 128 - (128 - wg_defaultDomainMask) - host.subnetPrefix`
	/// The domain applies to all of a peer's IPv6 addresses which come from the host.
	/// - Parameters
	/// 	- dk: The domain hash.
	/// 	- sk: The security key to be validated.
	public func domainMake(name:EncodedString) throws -> (NetworkV6, SecurityKey) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: name)
		// get the default domain mask size
		let maskNumber = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_defaultDomainMask.rawValue), as: RAW_byte.self, tx: newTrans)!
		
		var suggestedDomainSubnet:NetworkV6
		repeat {
			// Make the host specific bytes all 0's
			let address = try generateSecureRandomBytes(as: bedrock_ip.AddressV6.self)
			suggestedDomainSubnet = NetworkV6(bedrock_ip.NetworkV6(address: address, subnetPrefix: maskNumber.RAW_native()))
		} while try self.networkV6_domainHash.containsEntry(key: suggestedDomainSubnet, tx: newTrans)
		
		// write the domain and name to the database
		try self.domainHash_networkV6.setEntry(key: domainHash, value: suggestedDomainSubnet, flags: [.noOverwrite], tx: newTrans)
		try self.networkV6_domainHash.setEntry(key: suggestedDomainSubnet, value: domainHash, flags: [.noOverwrite], tx: newTrans)
		
		let securityKey = SecurityKey(randomBytes: try generateRandomBytes(count: MemoryLayout<SecurityKey>.size))!
		try self.domainHash_securityKey.setEntry(key: domainHash, value: securityKey, flags: [], tx: newTrans)
		
		try newTrans.commit()
		return (suggestedDomainSubnet, securityKey)
	}
	
	/// Remove a domain and all clients associated with the domain.
	/// - Parameters
	/// 	- name: The domain name.
	public func domainRemove(name:EncodedString) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: name)
		// get the domain of this network
		let domain = try domainHash_networkV6.loadEntry(key: domainHash, tx: newTrans)
		
		// delete the domains from the database
		try domainHash_networkV6.deleteEntry(key:domainHash, tx:newTrans)
		try networkV6_domainHash.deleteEntry(key:domain, tx:newTrans)
		try domainHash_securityKey.deleteEntry(key:domainHash, tx:newTrans)
		
		// remove any clients that may have belonged to this domain
		try domainHash_clientPub.cursor(tx: newTrans) { cursor in
			for (_, ourClientPubKey) in cursor.makeDupIterator(key: domainHash) {
				try self._clientRemove(publicKey: ourClientPubKey, tx: newTrans)
			}
		}
		
		try newTrans.commit()
	}
	
	public struct DomainInfo {
		public let name:EncodedString
		public let networks:[NetworkV6]
		public let securityKey:SecurityKey
	}
	
	public func allDomains() throws -> [DomainInfo] {
		let newTrans = try Transaction(env: env, readOnly: true)
		var domains = [DomainInfo]()
		
		let maskNumber = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_defaultDomainMask.rawValue), as: RAW_byte.self, tx: newTrans)!
		
		try addressName_hostSubnet.cursor(tx: newTrans) { hostCursor in
			try domainHash_securityKey.cursor(tx: newTrans) { securityKeyCursor in
				try domainHash_networkV6.cursor(tx: newTrans) { networkCursor in
					try domainHash_domainName.cursor(tx: newTrans) { nameCursor in
						for (hash, domainNetwork) in networkCursor.makeIterator() {
							let securityKey = try securityKeyCursor.opSet(key: hash)
							let name = try nameCursor.opSet(key: hash)
							var networks = [NetworkV6]()
							for (_, host) in hostCursor.makeIterator() {
								let addr = AddressV6((host.net.address & host.net.subnetMask) | (domainNetwork.net.address & ~host.net.subnetMask))
								networks.append(NetworkV6(bedrock_ip.NetworkV6(address: addr.addr, subnetPrefix: maskNumber.RAW_native())))
							}
							domains.append(DomainInfo(name: name, networks: networks, securityKey: securityKey))
						}
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
		return try self.domainHash_networkV6.containsEntry(key: domainHash, tx: newTrans)
	}
	
	fileprivate func _clientAssignIPv4(publicKey:PublicKey, tx:borrowing Transaction) throws -> AddressV4 {
		let myPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: tx)!
		guard myPubKey != publicKey else {
			throw WGDBError.immutableClient
		}
		let ipv4Subnet = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverIPv4Block.rawValue), as: NetworkV4.self, tx: tx)!
		var newV4:AddressV4
		repeat {
			newV4 = AddressV4(try ipv4Subnet.net.randomAddress())
		} while try self.ipv4_clientPub.containsEntry(key:newV4, tx:tx) == true
		try self.clientPub_ipv4.setEntry(key:publicKey, value:newV4, flags:[.noOverwrite], tx:tx)
		try self.ipv4_clientPub.setEntry(key:newV4, value:publicKey, flags:[.noOverwrite], tx:tx)
		return newV4
	}
	
	/// Creates and assigns a new IPv4 address for a client.
	/// - Parameters
	/// 	- domain: The domain of the client.
	/// 	- name: The human readable name of the client.
	public func clientAssignIPv4(domain:EncodedString, name:EncodedString) throws -> (AddressV4, AddressV6, PublicKey) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let domainHash = try DomainHash(domainName: domain)
		
		let ret = try self.domainHash_clientPub.cursor(tx: newTrans) { domainClientPubCursor in
			return try self.clientPub_clientName.cursor(tx: newTrans) { clientNameCursor in
				
				for (_, ourClientPubKey) in domainClientPubCursor.makeDupIterator(key: domainHash) {
					let clientName = try clientNameCursor.opSet(key: ourClientPubKey)
					
					if (clientName == name) {
						let existingAddress = try self.clientPub_ipv6.loadEntry(key: ourClientPubKey, tx: newTrans)
						return (try self._clientAssignIPv4(publicKey:ourClientPubKey, tx:newTrans), existingAddress, ourClientPubKey)
					}
				}
				throw LMDBError.notFound
			}
		}
		
		try newTrans.commit()
		return ret
	}
	
	fileprivate func _clientMake(name:EncodedString, publicKey:PublicKey, domain:EncodedString, ipv4:Bool, noHandshakeInvalidation:bedrock.Date.Seconds?, tx:borrowing Transaction) throws -> ([AddressV6], AddressV4?) {
		let domainHash = try DomainHash(domainName: domain)
		
		let domainNetwork = try domainHash_networkV6.loadEntry(key: domainHash, tx: tx)
		
		let v4Addr:AddressV4?
		if (ipv4) {
			v4Addr = try _clientAssignIPv4(publicKey: publicKey, tx: tx)
		} else {
			v4Addr = nil
		}
		
		var v6Addresses = [AddressV6]()
		try self.addressName_hostSubnet.cursor(tx: tx) { hostCursor in
			for (_, host) in hostCursor.makeIterator() {
				var newAddress:AddressV6
				repeat {
					newAddress = AddressV6((host.net.address & host.net.subnetMask) | (try domainNetwork.net.randomAddress() & ~host.net.subnetMask))
				} while try self.ipv6_clientPub.containsEntry(key:newAddress, tx:tx) == true
				v6Addresses.append(newAddress)
			}
		}
		
		try self.clientPub_clientName.setEntry(key: publicKey, value: name, flags: [.noOverwrite], tx: tx)
		try self.clientPub_createdOn.setEntry(key: publicKey, value: bedrock.Date.Seconds(), flags: [.noOverwrite], tx: tx)
		try self.clientPub_domainHash.setEntry(key: publicKey, value: domainHash, flags: [.noOverwrite], tx: tx)
		
		if noHandshakeInvalidation != nil {
			try self.clientPub_invalidDate.setEntry(key: publicKey, value: noHandshakeInvalidation!, flags: [.noOverwrite], tx: tx)
			log.info("new client invalidation date explicitly provided", metadata:["date":"\(noHandshakeInvalidation!)"])
		} else {
			let defaultInvalidation = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_noHandshakeInvalidationInterval.rawValue), as: EncodedTimeInterval.self, tx: tx)!
			let targetDate = bedrock.Date.Seconds().addingTimeInterval(defaultInvalidation.RAW_native())
			try self.clientPub_invalidDate.setEntry(key: publicKey, value: targetDate, flags: [.noOverwrite], tx: tx)
			log.info("new client invalidation date defined as a default value", metadata:["time_interval":"\(defaultInvalidation)", "target_date":"\(targetDate)"])
		}
		
		try self.domainHash_clientPub.setEntry(key: domainHash, value: publicKey, flags: [.noDupData], tx: tx)
		try self.domainHash_clientNameHash.setEntry(key: domainHash, value: ClientNameHash(clientName: name), flags: [.noDupData], tx: tx)
		
		return (v6Addresses, v4Addr)
	}
	
	/// Creates a new client with their ip addresses
	/// - Parameters
	/// 	- name: The name of the new client.
	/// 	- publicKey: The public key of the new client.
	/// 	- domain: The IPv6 domain of the client.
	/// 	- ipv4: An boolean indicating the creation of an IPv4 address for the client.
	/// 	- noHandshakeInvalidation: The date indicating when to delete the client if no handshakes have occured.
	/// 	- tx: The borrowed transaction on the environment.
	/// - Returns
	/// 	- [AddressV6]]: A list of the new IPv6 addresses for the client's [Interface] Address
	/// 	- AddressV4?: The IPv4 address (if provided) for the client's [Interface] Address
	public func clientMake(name:EncodedString, publicKey:PublicKey, domain:EncodedString, ipv4:Bool = false, noHandshakeInvalidation:bedrock.Date.Seconds? = nil) throws -> ([AddressV6], AddressV4?) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try _clientMake(name:name, publicKey:publicKey, domain:domain, ipv4:ipv4, noHandshakeInvalidation:noHandshakeInvalidation, tx:newTrans)
		try newTrans.commit()
		return ret
	}
	
	@discardableResult fileprivate func _clientRemove(publicKey:PublicKey, tx:borrowing Transaction) throws -> PublicKey {
		let myPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: tx)!
		guard myPubKey != publicKey else {
			throw WGDBError.immutableClient
		}
		
		let clientDomain = try self.clientPub_domainHash.loadEntry(key: publicKey, tx: tx)
		let clientName = try self.clientPub_clientName.loadEntry(key: publicKey, tx: tx)
		
		let hadIPv4:Bool
		do {
			let ipv4Addr = try self.clientPub_ipv4.loadEntry(key: publicKey, tx: tx)
			try self.clientPub_ipv4.deleteEntry(key: publicKey, tx: tx)
			try self.ipv4_clientPub.deleteEntry(key: ipv4Addr, tx: tx)
			hadIPv4 = true
		} catch LMDBError.notFound {
			hadIPv4 = false
		}
		
		try clientPub_ipv6.cursor(tx:tx) { cursor in
			for (_, ipv6Addr) in cursor.makeDupIterator(key: myPubKey) {
				try self.ipv6_clientPub.deleteEntry(key: ipv6Addr, tx: tx)
			}
		}
		try self.clientPub_ipv6.deleteEntry(key: publicKey, tx: tx)
		try self.clientPub_clientName.deleteEntry(key: publicKey, tx: tx)
		try self.clientPub_domainHash.deleteEntry(key: publicKey, tx: tx)
		
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
		try self.domainHash_clientPub.deleteEntry(key: clientDomain, tx: tx)
		try self.domainHash_clientNameHash.deleteEntry(key: clientDomain, tx: tx)
		
		// webserve code here if needed
		
		log.debug("successfully removed client from database", metadata:["public_key": "\(publicKey)", "client_name": "\(clientName)", "client_domain": "\(clientDomain)", "had_ipv4": "\(hadIPv4)", "did_handshake": "\(didHandshake)", "did_have_endpoint": "\(didCaptureEndpoint)" /*"had_webserve_config": "\(hadWebserveConfig)"*/])
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
		public let address:[AddressV6]
		public let addressV4:AddressV4?
		public let name:EncodedString
		public let domainName:EncodedString
		public let lastHandshake:bedrock.Date.Seconds?
		public let endpoint:Address?
		public let invalidationDate:bedrock.Date.Seconds
	}
	
	fileprivate func _allClients(domain:EncodedString? = nil, tx:borrowing Transaction) throws -> Set<ClientInfo> {
		var buildClients = Set<ClientInfo>()
		
		let serverPublicKey = try self.getServerPublicKey(tx)
		return try self.clientPub_ipv6.cursor(tx:tx) { clientAddressCursor in
			return try self.clientPub_clientName.cursor(tx:tx) { clientNameCursor in
				return try self.clientPub_domainHash.cursor(tx:tx) { clientDomainCursor in
					return try self.clientPub_handshakeDate.cursor(tx:tx) { clientHandshakeCursor in
						return try self.clientPub_endpointAddress.cursor(tx:tx) { clientEndpointCursor in
							return try self.clientPub_invalidDate.cursor(tx:tx) { clientInvalidationCursor in
								if domain == nil {
									for (ourClientKey, clientName) in clientNameCursor {
										let getDomain = try clientDomainCursor.opSet(key: ourClientKey)
										let domainName = try self.domainHash_domainName.loadEntry(key: getDomain, tx: tx)
										log.trace("current client selected", metadata:["name":"\(String(clientName))", "public_key":"\(ourClientKey.string)"])
										
										if serverPublicKey != ourClientKey {
											let addrv4:AddressV4?
											do {
												addrv4 = try clientPub_ipv4.loadEntry(key: ourClientKey, tx: tx)
											} catch LMDBError.notFound {
												addrv4 = nil
											}
											let lastHandshake:bedrock.Date.Seconds?
											do {
												lastHandshake = try clientHandshakeCursor.opSet(key: ourClientKey)
											} catch LMDBError.notFound {
												lastHandshake = nil
											}
											let endpoint:Address?
											do {
												endpoint = try clientEndpointCursor.opSet(key: ourClientKey)
											} catch LMDBError.notFound {
												endpoint = nil
											}
											let invalidationDate = try clientInvalidationCursor.opSet(key: ourClientKey)
											
											var ipv6Addresses = [AddressV6]()
											for (_, clientAddress) in clientAddressCursor.makeDupIterator(key: ourClientKey) {
												ipv6Addresses.append(clientAddress)
											}
											
											buildClients.update(with:ClientInfo(publicKey:ourClientKey, address:ipv6Addresses, addressV4:addrv4, name:clientName, domainName:domainName, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
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
												let addrv4:AddressV4?
												do {
													addrv4 = try clientPub_ipv4.loadEntry(key: clientPubKey, tx: tx)
												} catch LMDBError.notFound {
													addrv4 = nil
												}
												let lastHandshake:bedrock.Date.Seconds?
												do {
													lastHandshake = try clientHandshakeCursor.opSet(key: clientPubKey)
												} catch LMDBError.notFound {
													lastHandshake = nil
												}
												let endpoint:Address?
												do {
													endpoint = try clientEndpointCursor.opSet(key: clientPubKey)
												} catch LMDBError.notFound {
													endpoint = nil
												}
												let invalidationDate = try clientInvalidationCursor.opSet(key: clientPubKey)
												var ipv6Addresses = [AddressV6]()
												for (_, clientAddress) in clientAddressCursor.makeDupIterator(key: clientPubKey) {
													ipv6Addresses.append(clientAddress)
												}
												
												buildClients.update(with:ClientInfo(publicKey:clientPubKey, address:ipv6Addresses, addressV4:addrv4, name:clientName, domainName:domainName, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
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
	
	public func allClients(domain:EncodedString? = nil) throws -> Set<ClientInfo> {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try _allClients(domain:domain, tx:newTrans)
	}
	
	/// Returns whether the provided client name exists in the provided domain.
	/// - Parameters
	/// 	- domain: The name of the domain.
	/// 	- clientName: The name of the client to be validated.
	public func validateNewClientName(domain:EncodedString, clientName:EncodedString) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		let domainHash = try DomainHash(domainName: domain)
		if try domainHash_networkV6.containsEntry(key: domainHash, tx: newTrans) {
			if try domainHash_clientNameHash.containsEntry(key: domainHash, value: ClientNameHash(clientName: clientName), tx: newTrans) {
				return true
			}
		}
		return false
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
		try self.clientPub_invalidDate.setEntry(key: publicKey, value: targetDate, flags: .noOverwrite, tx: tx)
		
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
		case resolveIP(Address)
	}
	
	/// Processes all handshakes passed into the function. Moves invalidation dates accordingly.
	/// - Parameters
	/// 	- handshakes: The dictionary of the client's public key to the date the handshake occured.
	/// 	- endpoints: The dictionary of the client's public key to their endpoint address.
	/// 	- all: The complete set of client public keys.
	public func processHandshakes(_ handshakes:[PublicKey:bedrock.Date.Seconds], endpoints:[PublicKey:Address], all:Set<PublicKey>) throws -> [ProcessedHandshakeAction] {
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
