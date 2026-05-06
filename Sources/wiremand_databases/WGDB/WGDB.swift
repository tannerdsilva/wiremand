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
public struct AddressV4:Sendable, Hashable {
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
public struct NetworkV4:Sendable {
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
public struct AddressV6:Sendable, Hashable {
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
public struct NetworkV6:Sendable {
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
public struct SubnetHash:Sendable, Comparable {
	public init(subnetName:EncodedString) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(subnetName)
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
		/// The complete internal scope of the server's IPv6 address space. This is the complete address space that the server can assign to clients.
		case wg_serverIPv6Block = "wg_serverIPv6Subnet" //NetworkV6 where address == servers own internal IP
		/// The complete internal scope of the server's IPv4 address space. This is the complete address space that the server can assign to clients.
		case wg_serverIPv4Block = "wg_serverIPv4Subnet" //NetworkV4 where address == servers own internal IP
		/// The public key for the server.
		case wg_serverPublicKey = "serverPublicKey" //String
		/// The default subnet mask for the server. 
		///  - TODO: This really needs to be deleted and replaced with two different values for IPv4 and IPv6.
		case wg_defaultSubnetMask = "defaultSubnetMask" //UInt8
		/// The default invalidation interval 
		case wg_noHandshakeInvalidationInterval = "noHandshakeInvalidationInterval" //TimeInterval
		case wg_handshakeInvalidationInterval = "handshakeInvalidationInterval" //TimeInterval
		case wg_database_version = "wg_database_version" //UInt64
	}
	public enum Databases:String {
		case metadata = "wgdb_metadata_db"

		// client pub and address mappings
		case clientPub_ipv4 = "pub_4"
		case ipv4_clientPub = "4_pub"
		case clientPub_ipv6 = "pub_6"
		case ipv6_clientPub = "6_pub"
		
		case clientPub_clientName = "pub_name"
		case clientPub_createdOn = "pub_createDate"
		case subnetNameHash_subnetName = "subnetNameHash_subnetName"
		case clientPub_subnetNameHash = "pub_subnetNameHash"
		// Maps a client public key to their respective handshake date
		case clientPub_handshakeDate = "wgdb_clientPub_handshakeDate" //String:Date? (optional value)
		/// Maps a client public key to their respective endpoint address
		case clientPub_endpointAddress = "wgdb_clientPub_endpointAddr" //String:String? (optional value)
		/// Maps a client public key to their respective invalidation date
		case clientPub_invalidDate = "wgdb_clientPub_invalidDate" //String:Date (non-optional but not specified for the servers own public key since the server cannot invalidate itself)
		
		/// Maps a given subnet name to its respective IPv6 network
		case subnetHash_networkV6 = "wgdb_subnetHash_networkV6" //String:NetworkV6
		
		/// Maps a given subnet CIDR to its respective subnet name
		case networkV6_subnetName = "wgdb_networkV6_subnetName" //NetworkV6:String
		
		/// Maps a given subnet name hash to its respective security key
		/// - not specified on subnets that do not have the public api activated
		case subnetHash_securityKey = "wgdb_subnetHash_securityKey" //String:String
		
		/// Maps a given subnet name to the various public keys that it encompasses
		case subnetHash_clientPub = "wgdb_subnetHash_clientPub" //String:String
		
		/// Maps a given subnet name to the various client name that reside within it. This prevents name conflicts
		case subnetHash_clientNameHash = "wgdb_subnetHash_clientNameHash" //String:Data
		
		/// Maps a given client public key to the config data that may be served
		case webServe__clientPub_configData = "wgdb___webserve_clientPub_configData" //String:String
	}
	
	let log:Logger
	
	// basics
	let env:Environment
	let metadata:Database
	
	// client info ---------------------------
	// - optional ipv4 related databases
	let clientPub_ipv4:Database.Strict<PublicKey, AddressV4>
	let ipv4_clientPub:Database.Strict<AddressV4, PublicKey>
	
	// - required ipv6 related databases
	let clientPub_ipv6:Database.Strict<PublicKey, AddressV6>
	let ipv6_clientPub:Database.Strict<AddressV6, PublicKey>
	
	// - required client info
	let clientPub_clientName:Database.Strict<PublicKey, EncodedString>
	let clientPub_createdOn:Database.Strict<PublicKey, bedrock.Date.Seconds>

	// - required subnet info
	let subnetNameHash_subnetName:Database.Strict<SubnetHash, EncodedString>
	let clientPub_subnetNameHash:Database.Strict<PublicKey, SubnetHash>
	
	// - optional metadata about the client that is captured when the client connects to the network. this is not required for the client to be considered "valid" and "functional" in the system
	let clientPub_handshakeDate:Database.Strict<PublicKey, bedrock.Date.Seconds>
	let clientPub_endpointAddress:Database.Strict<PublicKey, Address>
	
	// - if the client is configured to be auto revoked, this is the date that it will be revoked.
	// 	- note: this database is only valid for clients that have connected to the network at least once. if a client has never connected to the network, it will not have a valid entry in this database, and any auto 
	let clientPub_invalidDate:Database.Strict<PublicKey, bedrock.Date.Seconds>
	
	// subnet info
	let subnetHash_networkV6:Database.Strict<SubnetHash, NetworkV6>
	let networkV6_subnetHash:Database.Strict<NetworkV6, SubnetHash>
	let subnetHash_securityKey:Database.Strict<SubnetHash, SecurityKey>
	
	// subnet + client info
	let subnetHash_clientPub:Database.DupSort<SubnetHash, PublicKey>
	let subnetHash_clientNameHash:Database.DupSort<SubnetHash, ClientNameHash>
	
	let webserve__clientPub_configData:Database.Strict<PublicKey, EncodedString>
	
	public func serveConfiguration(_ configString:EncodedString, forPublicKey publicKey:PublicKey) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		// confirm it exists
		_ = try clientPub_subnetNameHash.loadEntry(key: publicKey, tx: newTrans)
		try webserve__clientPub_configData.setEntry(key: publicKey, value: configString, flags: [.noOverwrite], tx: newTrans)
		try newTrans.commit()
	}
	public func getConfiguration(publicKey:PublicKey, subnetName:EncodedString) throws -> (configuration:EncodedString, name:EncodedString) {
		let newTrans = try Transaction(env: env, readOnly: true)
		let sh = try clientPub_subnetNameHash.loadEntry(key: publicKey, tx: newTrans)
		let subnetHash = try SubnetHash(subnetName: subnetName)
		guard sh == subnetHash else {
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
		log.critical("the existing database will be deleted and reinitialized without any data.")
		// try? FileManager.default.removeItem(at:envPath.path())
		let fileSize = envPath.getFileSize() + (16 * 1024 * 1024 * 1024) // current + 16GB
		env = try Environment(path:envPath.path(), flags:[.noSubDir], mapSize:Int(fileSize), maxReaders:32, maxDBs:32, mode:[.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])
		log.debug("successfully created environment", metadata:["mmap_size":"\(fileSize)b"])
		let someTrans = try Transaction(env:env, readOnly:false)
		log.trace("successfully created transaction")
		metadata = try Database(env:env, name:Databases.metadata.rawValue, flags:[.create], tx:someTrans)
		clientPub_ipv4 = try Database.Strict<PublicKey, AddressV4>(env:env, name:Databases.clientPub_ipv4.rawValue, flags:[.create], tx:someTrans)
		ipv4_clientPub = try Database.Strict<AddressV4, PublicKey>(env:env, name:Databases.ipv4_clientPub.rawValue, flags:[.create], tx:someTrans)
		clientPub_ipv6 = try Database.Strict<PublicKey, AddressV6>(env:env, name:Databases.clientPub_ipv6.rawValue, flags:[.create], tx:someTrans)
		ipv6_clientPub = try Database.Strict<AddressV6, PublicKey>(env:env, name:Databases.ipv6_clientPub.rawValue, flags:[.create], tx:someTrans)
		clientPub_clientName = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.clientPub_clientName.rawValue, flags:[.create], tx:someTrans)
		clientPub_createdOn = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_createdOn.rawValue, flags:[.create], tx:someTrans)
		subnetNameHash_subnetName = try Database.Strict<SubnetHash, EncodedString>(env:env, name:Databases.subnetNameHash_subnetName.rawValue, flags:[.create], tx:someTrans)
		clientPub_subnetNameHash = try Database.Strict<PublicKey, SubnetHash>(env:env, name:Databases.clientPub_subnetNameHash.rawValue, flags:[.create], tx:someTrans)
		clientPub_handshakeDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_handshakeDate.rawValue, flags:[.create], tx:someTrans)
		clientPub_endpointAddress = try Database.Strict<PublicKey, Address>(env:env, name:Databases.clientPub_endpointAddress.rawValue, flags:[.create], tx:someTrans)
		clientPub_invalidDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_invalidDate.rawValue, flags:[.create], tx:someTrans)
		subnetHash_networkV6 = try Database.Strict<SubnetHash, NetworkV6>(env:env, name:Databases.subnetHash_networkV6.rawValue, flags:[.create], tx:someTrans)
		networkV6_subnetHash = try Database.Strict<NetworkV6, SubnetHash>(env:env, name:Databases.networkV6_subnetName.rawValue, flags:[.create], tx:someTrans)
		subnetHash_securityKey = try Database.Strict<SubnetHash, SecurityKey>(env:env, name:Databases.subnetHash_securityKey.rawValue, flags:[.create], tx:someTrans)
		subnetHash_clientPub = try Database.DupSort<SubnetHash, PublicKey>(env:env, name:Databases.subnetHash_clientPub.rawValue, flags:[.create], tx:someTrans)
		subnetHash_clientNameHash = try Database.DupSort<SubnetHash, ClientNameHash>(env:env, name:Databases.subnetHash_clientNameHash.rawValue,	 flags:[.create], tx:someTrans)
		webserve__clientPub_configData = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.webServe__clientPub_configData.rawValue, flags:[.create], tx:someTrans)
		log.trace("successfully created databases")
		try someTrans.commit()
		log.info("successfully initialized WireguardDatabase")
	}
	
	public func install(wg_primaryInterfaceName:EncodedString, wg_serverPublicDomainName:EncodedString, wg_resolvedServerPublicIPv4:AddressV4, wg_resolvedServerPublicIPv6:AddressV6, wg_serverPublicListenPort:EncodedUInt16, serverIPv6Block:NetworkV6, serverIPv4Block:NetworkV4, publicKey:PublicKey, defaultSubnetMask:RAW_byte, noHandshakeInvalidationInterval:EncodedTimeInterval = EncodedTimeInterval(RAW_native: 3600), handshakeInvalidationInterval:EncodedTimeInterval = EncodedTimeInterval(RAW_native: 2629800)) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		
		let myClientName = EncodedString("localhost")
		let myAddress = AddressV6(serverIPv6Block.net.address)
		let mySubnet = NetworkV6(myAddress.string + "/\(defaultSubnetMask)")!
		let mySubnetName = wg_serverPublicDomainName
		let mySubnetHash = try SubnetHash(subnetName: mySubnetName)
		
		let myIPv4 = AddressV4(serverIPv4Block.net.address)
		
		try clientPub_ipv4.setEntry(key:publicKey, value:myIPv4, flags:[], tx:newTrans)
		try ipv4_clientPub.setEntry(key:myIPv4, value:publicKey, flags:[], tx:newTrans)
		try clientPub_ipv6.setEntry(key:publicKey, value:myAddress, flags:[], tx:newTrans)
		try ipv6_clientPub.setEntry(key:myAddress, value:publicKey, flags:[], tx:newTrans)
		try clientPub_clientName.setEntry(key:publicKey, value:myClientName, flags:[], tx:newTrans)
		try clientPub_createdOn.setEntry(key:publicKey, value:bedrock.Date.Seconds(), flags:[], tx:newTrans)
		try clientPub_subnetNameHash.setEntry(key:publicKey, value:mySubnetHash, flags:[], tx:newTrans)
		
		try subnetHash_networkV6.setEntry(key:mySubnetHash, value:mySubnet, flags: [], tx:newTrans)
		try networkV6_subnetHash.setEntry(key:mySubnet, value:mySubnetHash, flags: [], tx:newTrans)
		try subnetHash_securityKey.setEntry(key:mySubnetHash, value:try generateSecureRandomBytes(as: SecurityKey.self), flags:[], tx:newTrans)
		try subnetHash_clientPub.setEntry(key:mySubnetHash, value:publicKey, flags:[], tx:newTrans)
		try subnetHash_clientNameHash.setEntry(key: mySubnetHash, value: ClientNameHash(clientName: myClientName), flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), value: wg_primaryInterfaceName, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicDomainName.rawValue), value: wg_serverPublicDomainName, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv4Address.rawValue), value: wg_resolvedServerPublicIPv4, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicIPv6Address.rawValue), value: wg_resolvedServerPublicIPv6, flags: [], tx: newTrans)
		
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), value: wg_serverPublicListenPort, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverIPv6Block.rawValue), value: serverIPv6Block, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverIPv4Block.rawValue), value: serverIPv4Block, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), value: publicKey, flags: [], tx: newTrans)
		try metadata.setEntry(key: EncodedString(Metadatas.wg_defaultSubnetMask.rawValue), value: defaultSubnetMask, flags: [], tx: newTrans)
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
	
	public func getWireguardConfigMetas() throws -> (EncodedString, EncodedUInt16, NetworkV6, AddressV4, PublicKey, EncodedString, AddressV4?) {
		let newTrans = try Transaction(env: env, readOnly: true)
		let getDNSName = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicDomainName.rawValue), as: EncodedString.self, tx: newTrans)!
		let getPort = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicListenPort.rawValue), as: EncodedUInt16.self, tx: newTrans)!
		let ipv6Block = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverIPv6Block.rawValue), as: NetworkV6.self, tx: newTrans)!
		let ipv4Address = AddressV4(try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverIPv4Block.rawValue), as: NetworkV4.self, tx: newTrans)!.net.address)
		let serverPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: newTrans)!
		let publicInterfaceName = try metadata.loadEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), as: EncodedString.self, tx: newTrans)!
		let publicIPv4Interface:AddressV4?
		do {
			publicIPv4Interface = try metadata.loadEntry(key: EncodedString(Metadatas.wg_primaryInterfaceName.rawValue), as: AddressV4.self, tx: newTrans)
		} catch LMDBError.notFound {
			publicIPv4Interface = nil
		}
		return (getDNSName, getPort, ipv6Block, ipv4Address, serverPubKey, publicInterfaceName, publicIPv4Interface)
	}
	
	public func subnetMake(name:EncodedString) throws -> (NetworkV6, SecurityKey) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let subnetHash = try SubnetHash(subnetName: name)
		// get the default subnet mask size
		let maskNumber = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_defaultSubnetMask.rawValue), as: RAW_byte.self, tx: newTrans)!
		// get the servers ipv6 block
		let ipv6Block = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_serverIPv6Block.rawValue), as: NetworkV6.self, tx: newTrans)!
		
		// find a vacant subnet (subnet cannot already exist and subnet cannot overlap with the servers own internal IPv6 address)
		var suggestedSubnet:NetworkV6
		repeat {
			suggestedSubnet = NetworkV6(bedrock_ip.NetworkV6(address: try ipv6Block.net.randomAddress(), subnetPrefix: maskNumber.RAW_native()))
		} while try self.networkV6_subnetHash.containsEntry(key: suggestedSubnet, tx: newTrans)
		
		// write the subnet and name to the database
		try self.subnetHash_networkV6.setEntry(key: subnetHash, value: suggestedSubnet, flags: [.noOverwrite], tx: newTrans)
		try self.networkV6_subnetHash.setEntry(key: suggestedSubnet, value: subnetHash, flags: [.noOverwrite], tx: newTrans)
		
		let securityKey = try generateSecureRandomBytes(as: SecurityKey.self)
		try self.subnetHash_securityKey.setEntry(key: subnetHash, value: securityKey, flags: [], tx: newTrans)
		
		try newTrans.commit()
		return (suggestedSubnet, securityKey)
	}
	
	public func subnetRemove(name:EncodedString) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		let subnetHash = try SubnetHash(subnetName: name)
		// get the subnet of this network
		let subnet = try subnetHash_networkV6.loadEntry(key: subnetHash, tx: newTrans)
		
		// delete the subnets from the database
		try subnetHash_networkV6.deleteEntry(key:subnetHash, tx:newTrans)
		try networkV6_subnetHash.deleteEntry(key:subnet, tx:newTrans)
		try subnetHash_securityKey.deleteEntry(key:subnetHash, tx:newTrans)
		
		// remove any clients that may have belonged to this subnet
		try subnetHash_clientPub.cursor(tx: newTrans) { cursor in
			for (_, ourClientPubKey) in cursor.makeDupIterator(key: subnetHash) {
				try self._clientRemove(publicKey: ourClientPubKey, tx: newTrans)
			}
		}
		
		try newTrans.commit()
	}
	
	@discardableResult public func regenerateSecurityKey(subnet:EncodedString) throws -> SecurityKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let subnetHash = try SubnetHash(subnetName: subnet)
		
		let existingSecurityKey = try self.subnetHash_securityKey.loadEntry(key: subnetHash, tx: newTrans)
		var newSecurityKey = try generateSecureRandomBytes(as: SecurityKey.self)
		while newSecurityKey == existingSecurityKey {
			newSecurityKey = try generateSecureRandomBytes(as: SecurityKey.self)
		}
		try self.subnetHash_securityKey.setEntry(key: subnetHash, value: newSecurityKey, flags: [], tx: newTrans)
		
		try newTrans.commit()
		return newSecurityKey
	}
	
	// validate the security keys for a given subnet
	public func validateSecurity(dk subnetHash:SubnetHash, sk securityKey:SecurityKey) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		do {
			let currentSecurityKey = try self.subnetHash_securityKey.loadEntry(key: subnetHash, tx: newTrans)
			if (currentSecurityKey == securityKey) {
				return true
			} else {
				return false
			}
		} catch LMDBError.notFound {
			return false
		}
	}
	
	public struct SubnetInfo {
		public let name:EncodedString
		public let network:NetworkV6
		public let securityKey:SecurityKey
	}
	
	// get all the subnets in the database
	public func allSubnets() throws -> [SubnetInfo] {
		let newTrans = try Transaction(env: env, readOnly: true)
		var subnets = [SubnetInfo]()
		try subnetHash_securityKey.cursor(tx: newTrans) { securityKeyCursor in
			try subnetHash_networkV6.cursor(tx: newTrans) { networkCursor in
				try subnetNameHash_subnetName.cursor(tx: newTrans) { nameCursor in
					for (hash, name) in nameCursor.makeIterator() {
						let securityKey = try securityKeyCursor.opSet(key: hash)
						let network = try networkCursor.opSet(key: hash)
						subnets.append(SubnetInfo(name: name, network: network, securityKey: securityKey))
					}
				}
			}
		}
		return subnets
	}
	
	public func validateSubnet(name:EncodedString) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		let subnetHash = try SubnetHash(subnetName: name)
		return try self.subnetHash_networkV6.containsEntry(key: subnetHash, tx: newTrans)
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
	/// 	- subnet: The subnet of the client.
	/// 	- name: The human readable name of the client.
	public func clientAssignIPv4(subnet:EncodedString, name:EncodedString) throws -> (AddressV4, AddressV6, PublicKey) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let subnetHash = try SubnetHash(subnetName: subnet)
		
		let ret = try self.subnetHash_clientPub.cursor(tx: newTrans) { subnetClientPubCursor in
			return try self.clientPub_clientName.cursor(tx: newTrans) { clientNameCursor in
				
				for (_, ourClientPubKey) in subnetClientPubCursor.makeDupIterator(key: subnetHash) {
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
	
	/// Creates a new client with their ip addresses
	/// - Parameters
	/// 	- name: The name of the new client.
	/// 	- publicKey: The public key of the new client.
	/// 	- subnet: The IPv6 subnet of the client.
	/// 	- ipv4: An boolean indicating the creation of an IPv4 address for the client.
	/// 	- noHandshakeInvalidation: The date indicating when to delete the client if no handshakes have occured.
	/// 	- tx: The borrowed transaction on the environment.
	fileprivate func _clientMake(name:EncodedString, publicKey:PublicKey, subnet:EncodedString, ipv4:Bool, noHandshakeInvalidation:bedrock.Date.Seconds?, tx:borrowing Transaction) throws -> (AddressV6, AddressV4?) {
		let subnetHash = try SubnetHash(subnetName: subnet)
		let subnetNetwork = try subnetHash_networkV6.loadEntry(key: subnetHash, tx: tx)
		
		var newAddress:AddressV6
		repeat {
			newAddress = AddressV6(try subnetNetwork.net.randomAddress())
		} while try self.ipv6_clientPub.containsEntry(key:newAddress, tx:tx) == true
		
		let v4Addr:AddressV4?
		if (ipv4) {
			v4Addr = try _clientAssignIPv4(publicKey: publicKey, tx: tx)
		} else {
			v4Addr = nil
		}
		
		try self.clientPub_ipv6.setEntry(key: publicKey, value: newAddress, flags: [.noOverwrite], tx: tx)
		try self.ipv6_clientPub.setEntry(key: newAddress, value: publicKey, flags: [.noOverwrite], tx: tx)
		try self.clientPub_clientName.setEntry(key: publicKey, value: name, flags: [.noOverwrite], tx: tx)
		try self.clientPub_createdOn.setEntry(key: publicKey, value: bedrock.Date.Seconds(), flags: [.noOverwrite], tx: tx)
		try self.clientPub_subnetNameHash.setEntry(key: publicKey, value: subnetHash, flags: [.noOverwrite], tx: tx)
		
		if noHandshakeInvalidation != nil {
			try self.clientPub_invalidDate.setEntry(key: publicKey, value: noHandshakeInvalidation!, flags: [.noOverwrite], tx: tx)
			log.info("new client invalidation date explicitly provided", metadata:["date":"\(noHandshakeInvalidation!)"])
		} else {
			let defaultInvalidation = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_noHandshakeInvalidationInterval.rawValue), as: EncodedTimeInterval.self, tx: tx)!
			let targetDate = bedrock.Date.Seconds().addingTimeInterval(defaultInvalidation.RAW_native())
			try self.clientPub_invalidDate.setEntry(key: publicKey, value: targetDate, flags: [.noOverwrite], tx: tx)
			log.info("new client invalidation date defined as a default value", metadata:["time_interval":"\(defaultInvalidation)", "target_date":"\(targetDate)"])
		}
		
		try self.subnetHash_clientPub.setEntry(key: subnetHash, value: publicKey, flags: [.noDupData], tx: tx)
		try self.subnetHash_clientNameHash.setEntry(key: subnetHash, value: ClientNameHash(clientName: name), flags: [.noDupData], tx: tx)
		
		return (newAddress, v4Addr)
	}
	
	public func clientMake(name:EncodedString, publicKey:PublicKey, subnet:EncodedString, ipv4:Bool = false, noHandshakeInvalidation:bedrock.Date.Seconds? = nil) throws -> (AddressV6, AddressV4?) {
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try _clientMake(name:name, publicKey:publicKey, subnet:subnet, ipv4:ipv4, noHandshakeInvalidation:noHandshakeInvalidation, tx:newTrans)
		try newTrans.commit()
		return ret
	}
	
	@discardableResult fileprivate func _clientRemove(publicKey:PublicKey, tx:borrowing Transaction) throws -> PublicKey {
		let myPubKey = try metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicKey.rawValue), as: PublicKey.self, tx: tx)!
		guard myPubKey != publicKey else {
			throw WGDBError.immutableClient
		}
		
		let clientAddress = try self.clientPub_ipv6.loadEntry(key: publicKey, tx: tx)
		let clientSubnet = try self.clientPub_subnetNameHash.loadEntry(key: publicKey, tx: tx)
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
		
		try self.clientPub_ipv6.deleteEntry(key: publicKey, tx: tx)
		try self.ipv6_clientPub.deleteEntry(key: clientAddress, tx: tx)
		try self.clientPub_clientName.deleteEntry(key: publicKey, tx: tx)
		try self.clientPub_subnetNameHash.deleteEntry(key: publicKey, tx: tx)
		
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
		try self.subnetHash_clientPub.deleteEntry(key: clientSubnet, tx: tx)
		try self.subnetHash_clientNameHash.deleteEntry(key: clientSubnet, tx: tx)
		
		// webserve code here if needed
		
		log.debug("successfully removed client from database", metadata:["public_key": "\(publicKey)", "client_name": "\(clientName)", "client_subnet": "\(clientSubnet)", "had_ipv4": "\(hadIPv4)", "did_handshake": "\(didHandshake)", "did_have_endpoint": "\(didCaptureEndpoint)" /*"had_webserve_config": "\(hadWebserveConfig)"*/])
		return publicKey
	}
	
	@discardableResult public func clientRemove(publicKey:PublicKey) throws -> PublicKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try self._clientRemove(publicKey:publicKey, tx:newTrans)
		try newTrans.commit()
		return ret
	}
	@discardableResult public func clientRemove(subnet:EncodedString, name:EncodedString) throws -> PublicKey {
		let newTrans = try Transaction(env: env, readOnly: false)
		let subnetHash = try SubnetHash(subnetName: subnet)
		let ret = try clientPub_clientName.cursor(tx: newTrans) { cursor in
			return try subnetHash_clientNameHash.cursor(tx: newTrans) { subnetNameHashCursor in
				for (publicKey, clientName) in cursor.makeIterator() {
					if clientName == name {
						if try subnetNameHashCursor.containsEntry(key: subnetHash, value: ClientNameHash(clientName: clientName)) {
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
		public let address:AddressV6
		public let addressV4:AddressV4?
		public let name:EncodedString
		public let subnetName:EncodedString
		public let lastHandshake:bedrock.Date.Seconds?
		public let endpoint:Address?
		public let invalidationDate:bedrock.Date.Seconds
	}
	
	fileprivate func _allClients(subnet:EncodedString? = nil, tx:borrowing Transaction) throws -> Set<ClientInfo> {
		var buildClients = Set<ClientInfo>()
		
		let serverPublicKey = try self.getServerPublicKey(tx)
		return try self.clientPub_ipv6.cursor(tx:tx) { clientAddressCursor in
			return try self.clientPub_clientName.cursor(tx:tx) { clientNameCursor in
				return try self.clientPub_subnetNameHash.cursor(tx:tx) { clientSubnetCursor in
					return try self.clientPub_handshakeDate.cursor(tx:tx) { clientHandshakeCursor in
						return try self.clientPub_endpointAddress.cursor(tx:tx) { clientEndpointCursor in
							return try self.clientPub_invalidDate.cursor(tx:tx) { clientInvalidationCursor in
								if subnet == nil {
									for (ourClientKey, network) in clientAddressCursor {
										let getName = try clientNameCursor.opSet(key: ourClientKey)
										let getSubnet = try clientSubnetCursor.opSet(key: ourClientKey)
										let subnetName = try self.subnetNameHash_subnetName.loadEntry(key: getSubnet, tx: tx)
										log.trace("current client selected", metadata:["name":"\(getName)", "public_key":"\(ourClientKey)"])
										
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
											
											buildClients.update(with:ClientInfo(publicKey:ourClientKey, address:network, addressV4:addrv4, name:getName, subnetName:subnetName, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
										}
									}
									return buildClients
								} else {
									let subnetHash = try SubnetHash(subnetName: subnet!)
									let subnetName = try self.subnetNameHash_subnetName.loadEntry(key: subnetHash, tx: tx)
									try self.subnetHash_clientPub.cursor(tx:tx) { subnetNameCursor in
										for (_, clientPubKey) in subnetNameCursor.makeDupIterator(key: subnetHash) {
											let clientAddress = try clientAddressCursor.opSet(key: clientPubKey)
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
												
												buildClients.update(with:ClientInfo(publicKey:clientPubKey, address:clientAddress, addressV4:addrv4, name:clientName, subnetName:subnetName, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
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
	
	public func allClients(subnet:EncodedString? = nil) throws -> Set<ClientInfo> {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try _allClients(subnet:subnet, tx:newTrans)
	}
	
	fileprivate func allClientsWithImmutableSubnet(subnet:String? = nil) throws -> (Set<ClientInfo>, EncodedString, bedrock.Date.Seconds) {
		let newTrans = try Transaction(env: env, readOnly: true)
		let clients = try _allClients(tx:newTrans)
		let subnet = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_serverPublicDomainName.rawValue), as: EncodedString.self, tx: newTrans)!
		let invalidateTime = try self.metadata.loadEntry(key: EncodedString(Metadatas.wg_handshakeInvalidationInterval.rawValue), as: bedrock.Date.Seconds.self, tx: newTrans)!
		return (clients, subnet, invalidateTime)
	}
	
	public func validateNewClientName(subnet:EncodedString, clientName:EncodedString) throws -> Bool {
		let newTrans = try Transaction(env: env, readOnly: true)
		let subnetHash = try SubnetHash(subnetName: subnet)
		if try subnetHash_networkV6.containsEntry(key: subnetHash, tx: newTrans) {
			if try subnetHash_clientNameHash.containsEntry(key: subnetHash, value: ClientNameHash(clientName: clientName), tx: newTrans) {
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
	
	@discardableResult public func puntClientInvalidation(to newInvalidDate:bedrock.Date.Seconds? = nil, subnet:EncodedString, name:EncodedString) throws -> bedrock.Date.Seconds {
		let subnetHash = try SubnetHash(subnetName: subnet)
		let newTrans = try Transaction(env: env, readOnly: false)
		let ret = try self.subnetHash_clientPub.cursor(tx:newTrans) { subnetPubCursor in
			return try self.clientPub_clientName.cursor(tx:newTrans) { clientNameCursor in
				for (_, publicKey) in subnetPubCursor.makeDupIterator(key:subnetHash) {
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
	
	@discardableResult public func puntAllClients(subnet:EncodedString, to newInvalidDate:bedrock.Date.Seconds? = nil) throws -> bedrock.Date.Seconds {
		let newTrans = try Transaction(env: env, readOnly: false)
		let subnetHash = try SubnetHash(subnetName: subnet)
		let ret = try self.subnetHash_clientPub.cursor(tx:newTrans) { subnetPubCursor in
			var puntTo:bedrock.Date.Seconds? = newInvalidDate
			for (_, publicKey) in subnetPubCursor.makeDupIterator(key:subnetHash) {
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
		let getCurrentNetworkName = try self.clientPub_subnetNameHash.loadEntry(key: publicKey, tx: newTrans)
		let hashedName = try ClientNameHash(clientName: getCurrentName)
		
		try self.subnetHash_clientNameHash.deleteEntry(key: getCurrentNetworkName, value: hashedName, tx: newTrans)
		let newNameHash = try ClientNameHash(clientName: name)
		try self.subnetHash_clientNameHash.setEntry(key: getCurrentNetworkName, value: newNameHash, flags: [], tx: newTrans)
		
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
