import QuickLMDB
import AddressKit
import Foundation
import SystemPackage
import Logging
import SwiftBlake2

struct WireguardDatabase {
	fileprivate static func makeLogger() -> Logger {
		var newLogger = Logger(label:"wgdb")
		#if DEBUG
			newLogger.logLevel = .trace
		#else
			newLogger.logLevel = .info
		#endif
		return newLogger
	}
	internal static let logger = makeLogger()
	
	static let latestDBVersion = 0
	enum Error:Swift.Error {
		case immutableClient
	}
	fileprivate static func newSecurityKey() throws -> String {
		return try Self.generateRandomData().base64EncodedString()
	}
	static func createDatabase(environment:Environment, wg_primaryInterfaceName:String, wg_serverPublicDomainName:String, wg_resolvedServerPublicIPv4:AddressV4, wg_resolvedServerPublicIPv6:AddressV6, wg_serverPublicListenPort:UInt16, serverIPv6Block:NetworkV6, serverIPv4Block:NetworkV4, publicKey:String, defaultSubnetMask:UInt8, noHandshakeInvalidationInterval:TimeInterval = 3600, handshakeInvalidationInterval:TimeInterval = 2629800) throws {

		let makeEnv = environment
		try makeEnv.transact(readOnly: false) { someTransaction in
			let metadataDB = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[.create], tx:someTransaction)
			
			//make all the databases
			let clientPub_ipv4 = try makeEnv.openDatabase(named:Databases.clientPub_ipv4.rawValue, flags:[.create], tx:someTransaction)
			let ipv4_clientPub = try makeEnv.openDatabase(named:Databases.ipv4_clientPub.rawValue, flags:[.create], tx:someTransaction)
			let pub_ip6 = try makeEnv.openDatabase(named:Databases.clientPub_ipv6.rawValue, flags:[.create], tx:someTransaction)
			let ip6_pub = try makeEnv.openDatabase(named:Databases.ipv6_clientPub.rawValue, flags:[.create], tx:someTransaction)
			let pub_name = try makeEnv.openDatabase(named:Databases.clientPub_clientName.rawValue, flags:[.create], tx:someTransaction)
			let pub_create = try makeEnv.openDatabase(named:Databases.clientPub_createdOn.rawValue, flags:[.create], tx:someTransaction)
			let pub_subname = try makeEnv.openDatabase(named:Databases.clientPub_subnetName.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_handshakeDate.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_endpointAddress.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_invalidDate.rawValue, flags:[.create], tx:someTransaction)
			let subnetName_network = try makeEnv.openDatabase(named:Databases.subnetName_networkV6.rawValue, flags:[.create], tx:someTransaction)
			let network_subnetName = try makeEnv.openDatabase(named:Databases.networkV6_subnetName.rawValue, flags:[.create], tx:someTransaction)
			let subnetHash_securityKey = try makeEnv.openDatabase(named:Databases.subnetHash_securityKey.rawValue, flags:[.create], tx:someTransaction)
			let subnetName_clientPub = try makeEnv.openDatabase(named:Databases.subnetName_clientPub.rawValue, flags:[.create, .dupSort], tx:someTransaction)
			let subnetName_clientNameHash = try makeEnv.openDatabase(named:Databases.subnetName_clientNameHash.rawValue, flags:[.create, .dupSort], tx:someTransaction)
			
			_ = try makeEnv.openDatabase(named:Databases.webServe__clientPub_configData.rawValue, flags:[.create], tx:someTransaction)
			
			//install subnet and client info into this database. subnet is the wireguard public domain name, client name is 'localhost'
			let myClientName = "localhost"
			let myAddress = serverIPv6Block.address
			let mySubnet = NetworkV6(myAddress.string + "/\(defaultSubnetMask)")!.maskingAddress()
			let mySubnetName = wg_serverPublicDomainName
			let mySubnetHash = try WiremanD.hash(domain:mySubnetName)
			
			let myIPv4 = serverIPv4Block.address
			
			try clientPub_ipv4.setEntry(value:myIPv4, forKey:publicKey, tx:someTransaction)
			try ipv4_clientPub.setEntry(value:publicKey, forKey:myIPv4, tx:someTransaction)
			try pub_ip6.setEntry(value:myAddress, forKey:publicKey, tx:someTransaction)
			try ip6_pub.setEntry(value:publicKey, forKey:myAddress, tx:someTransaction)
			try pub_name.setEntry(value:myClientName, forKey:publicKey, tx:someTransaction)
			try pub_create.setEntry(value:Date(), forKey:publicKey, tx:someTransaction)
			try pub_subname.setEntry(value:mySubnetName, forKey:publicKey, tx:someTransaction)
			
			try subnetName_network.setEntry(value:mySubnet, forKey:mySubnetName, tx:someTransaction)
			try network_subnetName.setEntry(value:mySubnetName, forKey:mySubnet, tx:someTransaction)
			try subnetHash_securityKey.setEntry(value:try newSecurityKey(), forKey:mySubnetHash, tx:someTransaction)
			try subnetName_clientPub.setEntry(value:publicKey, forKey:mySubnetName, tx:someTransaction)
			try subnetName_clientNameHash.setEntry(value:try Self.hash(clientName:myClientName), forKey:mySubnetName, tx:someTransaction)
			
			//assign required metadata values
			try metadataDB.setEntry(value:wg_primaryInterfaceName, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:wg_serverPublicDomainName, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTransaction)
			
			try metadataDB.setEntry(value:wg_resolvedServerPublicIPv4, forKey:Metadatas.wg_serverPublicIPv4Address.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:wg_resolvedServerPublicIPv6, forKey:Metadatas.wg_serverPublicIPv6Address.rawValue, tx:someTransaction)
			
			try metadataDB.setEntry(value:wg_serverPublicListenPort, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:serverIPv6Block, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:serverIPv4Block, forKey:Metadatas.wg_serverIPv4Block.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:publicKey, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:defaultSubnetMask, forKey:Metadatas.wg_defaultSubnetMask.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:noHandshakeInvalidationInterval, forKey:Metadatas.wg_noHandshakeInvalidationInterval.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:handshakeInvalidationInterval, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:someTransaction)
			
			try metadataDB.setEntry(value:0, forKey:Metadatas.wg_database_version.rawValue, tx:someTransaction)
		}
	}
	
	enum Metadatas:String {
		/// The primary interface name for the wireguard interface.
		case wg_primaryInterfaceName = "wg_primaryWGInterfaceName" //String
		/// The public DNS name for the server.
		case wg_serverPublicDomainName = "wg_serverPublicDomainName" //String
		/// The public IPv4 address for the server.
		case wg_serverPublicIPv4Address = "wg_serverPublicIPv4Address" // AddressV4?
		/// The public IPv6 address for the server.
		case wg_serverPublicIPv6Address = "wg_serverPublicIPv6Address" // AddressV6?
		/// The public port that the wireguard process is listening on.
		case wg_serverPublicListenPort = "wg_serverPublicListenPort" //UInt16
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
	func primaryInterfaceName(_ tx:Transaction? = nil) throws -> String {
		return try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:tx)!
	}
	func getPublicEndpointName(_ tx:Transaction? = nil) throws -> String {
		return try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:tx)!
	}
	func getPublicListenPort(_ tx:Transaction? = nil) throws -> UInt16 {
		return try self.metadata.getEntry(type:UInt16.self, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:tx)!
	}
	func getServerInternalNetwork(_ tx:Transaction? = nil) throws -> NetworkV6 {
		return try self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:tx)!
	}
	func getServerIPv4Network(_ tx:Transaction? = nil) throws -> NetworkV4 {
		return try self.metadata.getEntry(type:NetworkV4.self, forKey:Metadatas.wg_serverIPv4Block.rawValue, tx:tx)!
	}
	func getServerPublicKey(_ tx:Transaction? = nil) throws -> String {
		return try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:tx)!
	}
	
	func getWireguardConfigMetas() throws -> (String, UInt16, NetworkV6, AddressV4, String, String, AddressV4?) {
		return try env.transact(readOnly:true) { someTrans -> (String, UInt16, NetworkV6, AddressV4, String, String, AddressV4?) in
			let getDNSName = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTrans)!
			let getPort = try metadata.getEntry(type:UInt16.self, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:someTrans)!
			let ipv6Block = try metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!
			let ipv4Address = try metadata.getEntry(type:NetworkV4.self, forKey:Metadatas.wg_serverIPv4Block.rawValue, tx:someTrans)!.address
			let serverPubKey = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:someTrans)!
			let publicInterfaceName = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:someTrans)!
			let publicIPv4Interface:AddressV4?
			do {
				publicIPv4Interface = try metadata.getEntry(type:AddressV4.self, forKey:Metadatas.wg_serverPublicIPv4Address.rawValue, tx:someTrans)!
			} catch LMDBError.notFound {
				publicIPv4Interface = nil
			}
			return (getDNSName, getPort, ipv6Block, ipv4Address, serverPubKey, publicInterfaceName, publicIPv4Interface)
		}
	}
	
	enum Databases:String {
		case metadata = "wgdb_metadata_db"

		// Client Databases
		/// Maps a client public key to their respective ipv4 address assignment (intended for small uses)
		case clientPub_ipv4 = "wgdb_clientPub_IPv4"	//String:AddressV4
		/// Maps a client ipv4 address assignment to their respective public key (intended for infrequent uses)
		case ipv4_clientPub = "wgdb_IPv4_clientPub"	//AddressV4:String
		/// Maps a client public key to their respective ipv6 address assignment
		case clientPub_ipv6 = "wgdb_clientPub_IPv6" //String:AddressV6
		// Maps a client ipv6 address to their public key
		case ipv6_clientPub = "wgdb_IPv6_clientPub" //AddressV6:String
		/// Maps a client public key to their respective client name
		case clientPub_clientName = "wgdb_clientPub_clientName" //String:String
		/// Maps a client public key to their keys respective creation date
		case clientPub_createdOn = "wgdb_clientPub_createDate" //String:Date
		/// Maps a client public key to their respective subnet
		case clientPub_subnetName = "wgdb_clientPub_subnetName" //String:String
		// Maps a client public key to their respective handshake date
		case clientPub_handshakeDate = "wgdb_clientPub_handshakeDate" //String:Date? (optional value)
		/// Maps a client public key to their respective endpoint address
		case clientPub_endpointAddress = "wgdb_clientPub_endpointAddr" //String:String? (optional value)
		/// Maps a client public key to their respective invalidation date
		case clientPub_invalidDate = "wgdb_clientPub_invalidDate" //String:Date (non-optional but not specified for the servers own public key since the server cannot invalidate itself)
		
		/// Maps a given subnet name to its respective IPv6 network
		case subnetName_networkV6 = "wgdb_subnetName_networkV6" //String:NetworkV6
		
		/// Maps a given subnet CIDR to its respective subnet name
		case networkV6_subnetName = "wgdb_networkV6_subnetName" //NetworkV6:String
		
		/// Maps a given subnet name hash to its respective security key
		/// - not specified on subnets that do not have the public api activated
		case subnetHash_securityKey = "wgdb_subnetHash_securityKey" //String:String
		
		/// Maps a given subnet name to the various public keys that it encompasses
		case subnetName_clientPub = "wgdb_subnetName_clientPub" //String:String
		
		/// Maps a given subnet name to the various client name that reside within it. This prevents name conflicts
		case subnetName_clientNameHash = "wgdb_subnetName_clientNameHash" //String:Data
		
		/// Maps a given client public key to the config data that may be served
		case webServe__clientPub_configData = "wgdb___webserve_clientPub_configData" //String:String
	}
	
	// basics
	let env:Environment
	let metadata:Database
	
	// client info ---------------------------
	// - optional ipv4 related databases
	let clientPub_ipv4:Database
	let ipv4_clientPub:Database
	// - required ipv6 related databases
	let clientPub_ipv6:Database
	let ipv6_clientPub:Database
	// - required client info
	let clientPub_clientName:Database
	let clientPub_createdOn:Database
	let clientPub_subnetName:Database
	// - optional metadata about the client that is captured when the client connects to the network. this is not required for the client to be considered "valid" and "functional" in the system
	let clientPub_handshakeDate:Database
	let clientPub_endpointAddress:Database
	// - if the client is configured to be auto revoked, this is the date that it will be revoked.
	// 	- note: this database is only valid for clients that have connected to the network at least once. if a client has never connected to the network, it will not have a valid entry in this database, and any auto 
	let clientPub_invalidDate:Database
	
	// subnet info
	let subnetName_networkV6:Database
	let networkV6_subnetName:Database
	let subnetHash_securityKey:Database
	
	// subnet + client info
	let subnetName_clientPub:Database
	let subnetName_clientNameHash:Database
	
	// webserve for configs
	let webserve__clientPub_configData:Database
	func serveConfiguration(_ configString:String, forPublicKey publicKey:String) throws {
		try env.transact(readOnly:false) { someTrans in
			// validate that the current public key exists
			_ = try clientPub_subnetName.getEntry(type:String.self, forKey:publicKey, tx:someTrans)!

			// write the data into the webserve databases
			try webserve__clientPub_configData.setEntry(value:configString, forKey:publicKey, flags:[.noOverwrite], tx:someTrans)
		}
	}
	func getConfiguration(publicKey:String, subnetName:String) throws -> (configuration:String, name:String) {
		try env.transact(readOnly:true) { someTrans in
			// check the subnet name and validate that it matches
			let sn = try clientPub_subnetName.getEntry(type:String.self, forKey:publicKey, tx:someTrans)!
			guard subnetName == sn else {
				throw LMDBError.notFound
			}
			let getName = try clientPub_clientName.getEntry(type:String.self, forKey:publicKey, tx:someTrans)!
			return (configuration:try self.webserve__clientPub_configData.getEntry(type:String.self, forKey:publicKey, tx:someTrans)!, name:getName)
		}
	}
	
	init(environment:Environment) throws {
		let makeEnv = environment
		self.env = makeEnv
		let someTrans = try Transaction(makeEnv, readOnly:true)
		// open all the databases
		self.metadata = try makeEnv.openDatabase(named:Databases.metadata.rawValue, tx:someTrans)
		// open the client databases
		self.clientPub_ipv4 = try! makeEnv.openDatabase(named:Databases.clientPub_ipv4.rawValue, tx:someTrans)
		self.ipv4_clientPub = try! makeEnv.openDatabase(named:Databases.ipv4_clientPub.rawValue, tx:someTrans)
		self.clientPub_ipv6 = try! makeEnv.openDatabase(named:Databases.clientPub_ipv6.rawValue, tx:someTrans)
		self.ipv6_clientPub = try! makeEnv.openDatabase(named:Databases.ipv6_clientPub.rawValue, tx:someTrans)
		self.clientPub_clientName = try! makeEnv.openDatabase(named:Databases.clientPub_clientName.rawValue, tx:someTrans)
		self.clientPub_createdOn = try! makeEnv.openDatabase(named:Databases.clientPub_createdOn.rawValue, tx:someTrans)
		self.clientPub_subnetName = try! makeEnv.openDatabase(named:Databases.clientPub_subnetName.rawValue, tx:someTrans)
		self.clientPub_handshakeDate = try! makeEnv.openDatabase(named:Databases.clientPub_handshakeDate.rawValue, tx:someTrans)
		self.clientPub_endpointAddress = try! makeEnv.openDatabase(named:Databases.clientPub_endpointAddress.rawValue, tx:someTrans)
		self.clientPub_invalidDate = try! makeEnv.openDatabase(named:Databases.clientPub_invalidDate.rawValue, tx:someTrans)

		// open the subnet databases
		self.subnetName_networkV6 = try! makeEnv.openDatabase(named:Databases.subnetName_networkV6.rawValue, tx:someTrans)
		self.networkV6_subnetName = try! makeEnv.openDatabase(named:Databases.networkV6_subnetName.rawValue, tx:someTrans)
		self.subnetHash_securityKey = try! makeEnv.openDatabase(named:Databases.subnetHash_securityKey.rawValue, tx:someTrans)
		self.subnetName_clientPub = try! makeEnv.openDatabase(named:Databases.subnetName_clientPub.rawValue, flags:[.dupSort], tx:someTrans)
		self.subnetName_clientNameHash = try! makeEnv.openDatabase(named:Databases.subnetName_clientNameHash.rawValue, flags:[.dupSort], tx:someTrans)
		self.webserve__clientPub_configData = try! makeEnv.openDatabase(named:Databases.webServe__clientPub_configData.rawValue, tx:someTrans)
		try someTrans.commit()
		Self.logger.debug("instance initialized successfully.")
	}
	
	// subnet info container
	struct SubnetInfo {
		let name:String
		let network:NetworkV6
		let securityKey:String
	}
	
	// create subnet
	func subnetMake(name:String) throws -> (NetworkV6, String) {
		return try env.transact(readOnly:false) { someTrans in
			// get the default subnet mask size
			let maskNumber = try self.metadata.getEntry(type:UInt8.self, forKey:Metadatas.wg_defaultSubnetMask.rawValue, tx:someTrans)!
			// get the servers ipv6 block
			let ipv6Block = try self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!

			// find a vacant subnet (subnet cannot already exist and subnet cannot overlap with the servers own internal IPv6 address)
			var suggestedSubnet:NetworkV6
			repeat {
				suggestedSubnet = NetworkV6(cidr:ipv6Block.range.randomAddress().string + "/\(maskNumber)")!.maskingAddress()
			} while try self.networkV6_subnetName.containsEntry(key:suggestedSubnet, tx:someTrans) == true
			
			// write the subnet and name to the database
			try self.subnetName_networkV6.setEntry(value:suggestedSubnet, forKey:name, flags:[.noOverwrite], tx:someTrans)
			try self.networkV6_subnetName.setEntry(value:name, forKey:suggestedSubnet, flags:[.noOverwrite], tx:someTrans)
			
			let randomString = try Self.newSecurityKey()
			let domainHash = try WiremanD.hash(domain:name)
			try self.subnetHash_securityKey.setEntry(value:randomString, forKey:domainHash, tx:someTrans)
			return (suggestedSubnet, randomString)
		}
	}
	
	// remove subnet
	func subnetRemove(name:String) throws {
		try env.transact(readOnly:false) { someTrans in
			// get the subnet of this network
			let subnet = try subnetName_networkV6.getEntry(type:NetworkV6.self, forKey:name, tx:someTrans)!
			
			// delete the subnets from the database
			try subnetName_networkV6.deleteEntry(key:name, tx:someTrans)
			try networkV6_subnetName.deleteEntry(key:subnet, tx:someTrans)
			let subnetHash = try WiremanD.hash(domain:name)
			try subnetHash_securityKey.deleteEntry(key:subnetHash, tx: someTrans)
			
			// remove any clients that may have belonged to this subnet
			let subnetName_clientPubCursor = try subnetName_clientPub.cursor(tx:someTrans)
			for curClient in try subnetName_clientPubCursor.makeDupIterator(key:name) {
				try self._clientRemove(publicKey:String(curClient.value)!, tx:someTrans)
			}
		}
	}
	
	// secure an existing domain
	@discardableResult func regenerateSecurityKey(subnet:String) throws -> String {
		try env.transact(readOnly:false) { someTrans in
			let subnetHash = try WiremanD.hash(domain:subnet)
			
			// check that the subnet exists by trying to read its existing security key
			let existingData = try self.subnetHash_securityKey.getEntry(type:Data.self, forKey:subnetHash, tx:someTrans)
			
			// generate new data and validate that it is unique from the previous key
			var newData = try Self.generateRandomData()
			while newData == existingData {
				newData = try Self.generateRandomData()
			}
			
			// assign a new security key
			try self.subnetHash_securityKey.setEntry(value:newData, forKey:subnetHash, tx:someTrans)
			
			return newData.base64EncodedString()
		}
	}
	
	// validate the security keys for a given subnet
	func validateSecurity(dk subnetHash:String, sk securityKey:String) throws -> Bool {
		return try env.transact(readOnly:true) { someTrans in
			do {
				let currentSecurityKey = try self.subnetHash_securityKey.getEntry(type:String.self, forKey:subnetHash, tx:someTrans)
				if (currentSecurityKey == securityKey) {
					return true
				} else {
					return false
				}
			} catch LMDBError.notFound {
				return false
			}
		}
	}
	// get all the subnets in the database
	func allSubnets() throws -> [SubnetInfo] {
		return try env.transact(readOnly:true) { someTrans in
			let subnetNameCursor = try subnetName_networkV6.cursor(tx:someTrans)
			let securityKeyCursor = try subnetHash_securityKey.cursor(tx:someTrans)
			var buildSubnets = [SubnetInfo]()
			for curKV in subnetNameCursor {
				let name = String(curKV.key)!
				let hashed = try WiremanD.hash(domain:name)
				let securityKey:String = String(try securityKeyCursor.getEntry(.set, key:hashed).value)!
				buildSubnets.append(SubnetInfo(name:name, network:NetworkV6(curKV.value)!, securityKey:securityKey))
			}
			return buildSubnets
		}
	}
	func validateSubnet(name:String) throws -> Bool {
		try env.transact(readOnly:true) { someTrans in
			return try self.subnetName_networkV6.containsEntry(key:name, tx:someTrans)
		}
	}
	
	// make a client
	struct ClientInfo:Hashable {
		let publicKey:String
		let address:AddressV6
		let addressV4:AddressV4?
		let name:String
		let subnetName:String
		let lastHandshake:Date?
		let endpoint:String?
		let invalidationDate:Date
	}
	// INTERNAL FUNCTION: Assigns an IPv4 address to an existing client. This function does not check if the public key is valid!
	fileprivate func _clientAssignIPv4(publicKey:String, tx:Transaction) throws -> AddressV4 {
		let myPubKey = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:tx)!
		guard myPubKey != publicKey else {
			throw Error.immutableClient
		}
		let ipv4Subnet = try metadata.getEntry(type:NetworkV4.self, forKey:Metadatas.wg_serverIPv4Block.rawValue, tx:tx)!
		var newV4:AddressV4
		repeat {
			newV4 = ipv4Subnet.range.randomAddress()
		} while try self.ipv4_clientPub.containsEntry(key:newV4, tx:tx) == true
		try self.clientPub_ipv4.setEntry(value:newV4, forKey:publicKey, flags:[.noOverwrite], tx:tx)
		try self.ipv4_clientPub.setEntry(value:publicKey, forKey:newV4, flags:[.noOverwrite], tx:tx)
		return newV4
	}
	func clientAssignIPv4(subnet:String, name:String) throws -> (AddressV4, AddressV6, String) {
		try env.transact(readOnly:false) { someTrans in
			let subnetClientsCursor = try self.subnetName_clientPub.cursor(tx:someTrans)
			let clientNameCursor = try self.clientPub_clientName.cursor(tx:someTrans)
			
			for curClient in try subnetClientsCursor.makeDupIterator(key:subnet) {
				let nameString = String(try clientNameCursor.getEntry(.set, key:curClient.value).value)!
				if (nameString == name) {
					let pubString = String(curClient.value)!
					let existingAddress = try self.clientPub_ipv6.getEntry(type:AddressV6.self, forKey:pubString, tx:someTrans)!
					return (try self._clientAssignIPv4(publicKey:pubString, tx:someTrans), existingAddress, pubString)
				}
			}
			throw LMDBError.notFound
		}
	}
	
	fileprivate func _clientMake(name:String, publicKey:String, subnet:String, ipv4:Bool, noHandshakeInvalidation:Date?, tx:Transaction) throws -> (AddressV6, AddressV4?) {
		// validate the subnet exists by retrieving its network
		let subnetNetwork = try subnetName_networkV6.getEntry(type:NetworkV6.self, forKey:subnet, tx:tx)!
		
		// find a non-conflicting address
		var newAddress:AddressV6
		repeat {
			newAddress = subnetNetwork.range.randomAddress()
		} while try self.ipv6_clientPub.containsEntry(key:newAddress, tx:tx) == true
		
		let v4Addr:AddressV4?
		if (ipv4) {
			v4Addr = try _clientAssignIPv4(publicKey:publicKey, tx:tx)
		} else {
			v4Addr = nil
		}
		
		// write it to the database
		try self.clientPub_ipv6.setEntry(value:newAddress, forKey:publicKey, flags:[.noOverwrite], tx:tx)
		try self.ipv6_clientPub.setEntry(value:publicKey, forKey:newAddress, flags:[.noOverwrite], tx:tx)
		try self.clientPub_clientName.setEntry(value:name, forKey:publicKey, flags:[.noOverwrite], tx:tx)
		try self.clientPub_createdOn.setEntry(value:Date(), forKey:publicKey, flags:[.noOverwrite], tx:tx)
		try self.clientPub_subnetName.setEntry(value:subnet, forKey:publicKey, flags:[.noOverwrite], tx:tx)
		
		if (noHandshakeInvalidation != nil) {
			try self.clientPub_invalidDate.setEntry(value:noHandshakeInvalidation!, forKey:publicKey, flags:[.noOverwrite], tx:tx)
			WiremanD.appLogger.info("new client invalidation date explicitly provided", metadata:["date":"\(noHandshakeInvalidation!)"])
		} else {
			let defaultInvalidation = try self.metadata.getEntry(type:TimeInterval.self, forKey:Metadatas.wg_noHandshakeInvalidationInterval.rawValue, tx:tx)!
			let targetDate = Date().addingTimeInterval(defaultInvalidation)
			try self.clientPub_invalidDate.setEntry(value:targetDate, forKey:publicKey, flags:[.noOverwrite], tx:tx)
			WiremanD.appLogger.info("new client invalidation date defined as a default value", metadata:["time_interval":"\(defaultInvalidation)", "target_date":"\(targetDate)"])
		}
		
		try self.subnetName_clientPub.setEntry(value:publicKey, forKey:subnet, flags:[.noDupData], tx:tx)
		try self.subnetName_clientNameHash.setEntry(value:try Self.hash(clientName:name), forKey:subnet, flags:[.noDupData], tx:tx)
		return (newAddress, v4Addr)
	}
	func clientMake(name:String, publicKey:String, subnet:String, ipv4:Bool = false, noHandshakeInvalidation:Date? = nil) throws -> (AddressV6, AddressV4?) {
		return try env.transact(readOnly:false) { someTrans in
			return try _clientMake(name:name, publicKey:publicKey, subnet:subnet, ipv4:ipv4, noHandshakeInvalidation:noHandshakeInvalidation, tx:someTrans)
		}
	}
	@discardableResult fileprivate func _clientRemove(publicKey:String, tx:Transaction) throws -> String {
		// validate that our own key is not being removed
		let myPubKey = try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:tx)!
		guard publicKey != myPubKey else {
			throw Error.immutableClient
		}
		// get the clients address
		let clientAddress = try self.clientPub_ipv6.getEntry(type:AddressV6.self, forKey:publicKey, tx:tx)!
		let clientSubnet = try self.clientPub_subnetName.getEntry(type:String.self, forKey:publicKey, tx:tx)!
		let clientName = try self.clientPub_clientName.getEntry(type:String.self, forKey:publicKey, tx:tx)!
		
		let hadIPv4:Bool
		// remove the ipv4 address if the client had one
		do {
			let ipv4Addr = try self.clientPub_ipv4.getEntry(type:AddressV4.self, forKey:publicKey, tx:tx)!
			try self.clientPub_ipv4.deleteEntry(key:publicKey, tx:tx)
			try self.ipv4_clientPub.deleteEntry(key:ipv4Addr, tx:tx)
			hadIPv4 = true
		} catch LMDBError.notFound {
			hadIPv4 = false
		}
		
		// with this info we can delete everything else from the database
		try self.clientPub_ipv6.deleteEntry(key:publicKey, tx:tx)
		try self.ipv6_clientPub.deleteEntry(key:clientAddress, tx:tx)
		try self.clientPub_clientName.deleteEntry(key:publicKey, tx:tx)
		try self.clientPub_subnetName.deleteEntry(key:publicKey, tx:tx)
		
		let didHandshake:Bool
		do {
			// handshake date may have never been written to the database
			try self.clientPub_handshakeDate.deleteEntry(key:publicKey, tx:tx)
			didHandshake = true
		} catch LMDBError.notFound {
			didHandshake = false
		}
		let didCaptureEndpoint:Bool
		do {
			// endpoint may have never been written to the database
			try self.clientPub_endpointAddress.deleteEntry(key:publicKey, tx:tx)
			didCaptureEndpoint = true
		} catch LMDBError.notFound {
			didCaptureEndpoint = false
		}
		try self.clientPub_invalidDate.deleteEntry(key:publicKey, tx:tx)
		try self.subnetName_clientPub.deleteEntry(key:clientSubnet, value:publicKey, tx:tx)
		try self.subnetName_clientNameHash.deleteEntry(key:clientSubnet, value:try Self.hash(clientName:clientName), tx:tx)
		let hadWebserveConfig:Bool
		do {
			try self.webserve__clientPub_configData.deleteEntry(key:publicKey, tx:tx)
			hadWebserveConfig = true
		} catch LMDBError.notFound {
			hadWebserveConfig = false
		}
		WiremanD.appLogger.debug("successfully removed client from database", metadata:["public_key": "\(publicKey)", "client_name": "\(clientName)", "client_subnet": "\(clientSubnet)", "had_ipv4": "\(hadIPv4)", "did_handshake": "\(didHandshake)", "did_have_endpoint": "\(didCaptureEndpoint)", "had_webserve_config": "\(hadWebserveConfig)"])
		return publicKey
	}
	@discardableResult func clientRemove(publicKey:String) throws -> String {
		return try env.transact(readOnly:false) { someTrans in
			return try self._clientRemove(publicKey:publicKey, tx:someTrans)
		}
	}
	@discardableResult func clientRemove(subnet:String, name:String) throws -> String {
		return try env.transact(readOnly:false) { someTrans in
			let getName = try self.clientPub_clientName.cursor(tx:someTrans)
			let subnetNameHashCursor = try self.subnetName_clientNameHash.cursor(tx:someTrans)
			
			// loop through every client - find a client with a matching name
			for kv in getName {
				let nameString = String(kv.value)!
				if name == nameString {
					
					// name matched - now confirm this client belongs to the subnet that we are trying to target
					let nameHash = try Self.hash(clientName:nameString)
					if try subnetNameHashCursor.containsEntry(key:subnet, value:nameHash) == true {
						try _clientRemove(publicKey:String(kv.key)!, tx:someTrans)
						return String(kv.key)!
					}
				}
			}
			throw LMDBError.notFound
		}
	}
	
	fileprivate func _allClients(subnet:String? = nil, tx:Transaction) throws -> Set<ClientInfo> {
		var buildClients = Set<ClientInfo>()
		let serverPublicKey = try self.getServerPublicKey(tx)
		let clientAddressCursor = try self.clientPub_ipv6.cursor(tx:tx)
		let clientNameCursor = try self.clientPub_clientName.cursor(tx:tx)
		let clientSubnetCursor = try self.clientPub_subnetName.cursor(tx:tx)
		let clientHandshakeCursor = try self.clientPub_handshakeDate.cursor(tx:tx)
		let clientEndpointCursor = try self.clientPub_endpointAddress.cursor(tx:tx)
		let clientInvalidationCursor = try self.clientPub_invalidDate.cursor(tx:tx)
		if (subnet == nil) {
			// all clients are requested
			WiremanD.appLogger.trace("listing all clients", metadata:["server_pub_key":"\(serverPublicKey)"])
			for curClient in clientAddressCursor {
				let getName = String(try! clientNameCursor.getEntry(.set, key:curClient.key).value)!
				
				let getSubnet = String(try! clientSubnetCursor.getEntry(.set, key:curClient.key).value)!
				let publicKey = String(curClient.key)!
				WiremanD.appLogger.trace("current client selected", metadata:["name":"\(getName)", "public_key":"\(publicKey)"])
				
				if serverPublicKey != publicKey {
					let address = AddressV6(curClient.value)!
					let addrv4:AddressV4?
					do {
						addrv4 = try clientPub_ipv4.getEntry(type:AddressV4.self, forKey:publicKey, tx:tx)!
					} catch LMDBError.notFound {
						addrv4 = nil
					}
					let lastHandshake:Date?
					do {
						lastHandshake = Date(try clientHandshakeCursor.getEntry(.set, key:publicKey).value)
					} catch LMDBError.notFound {
						lastHandshake = nil
					}
					let endpoint:String?
					do {
						endpoint = String(try clientEndpointCursor.getEntry(.set, key:publicKey).value)
					} catch LMDBError.notFound {
						endpoint = nil
					}
					let invalidationDate = Date(try! clientInvalidationCursor.getEntry(.set, key:publicKey).value)!
					buildClients.update(with:ClientInfo(publicKey:publicKey, address:address, addressV4:addrv4, name:getName, subnetName:getSubnet, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
				}
			}
			return buildClients
		} else {
			// only the clients of a certain subnet are requested
			let subnetNameCursor = try self.subnetName_clientPub.cursor(tx:tx)
			do {
				_ = try subnetNameCursor.getEntry(.set, key:subnet!)
				var operation = Cursor.Operation.firstDup
				repeat {
					let getCurrentPub = try subnetNameCursor.getEntry(operation).value
					let clientAddress = AddressV6(try clientAddressCursor.getEntry(.set, key:getCurrentPub).value)!
					let clientName = String(try clientNameCursor.getEntry(.set, key:getCurrentPub).value)!
					let publicKey = String(getCurrentPub)!
					if serverPublicKey != publicKey {
						let addrv4:AddressV4?
						do {
							addrv4 = try clientPub_ipv4.getEntry(type:AddressV4.self, forKey:publicKey, tx:tx)!
						} catch LMDBError.notFound {
							addrv4 = nil
						}
						let lastHandshake:Date?
						do {
							lastHandshake = Date(try clientHandshakeCursor.getEntry(.set, key:publicKey).value)
						} catch LMDBError.notFound {
							lastHandshake = nil
						}
						let endpoint:String?
						do {
							endpoint = String(try clientEndpointCursor.getEntry(.set, key:publicKey).value)
						} catch LMDBError.notFound {
							endpoint = nil
						}
						let invalidationDate = Date(try clientInvalidationCursor.getEntry(.set, key:publicKey).value)!
						buildClients.update(with:ClientInfo(publicKey:String(getCurrentPub)!, address:clientAddress, addressV4:addrv4, name:clientName, subnetName:subnet!, lastHandshake:lastHandshake, endpoint:endpoint, invalidationDate:invalidationDate))
					}
					switch operation {
					case .firstDup:
						operation = .nextDup
					default:
						break;
					}
				} while true
			} catch LMDBError.notFound {
				if (try self.subnetName_networkV6.containsEntry(key:subnet!, tx:tx) == false) {
					throw LMDBError.notFound
				}
			}
			return buildClients
		}
	}
	func allClients(subnet:String? = nil) throws -> Set<ClientInfo> {
		try env.transact(readOnly:true) { someTrans in
			return try _allClients(subnet:subnet, tx:someTrans)
		}
	}
	fileprivate func allClientsWithImmutableSubnet(subnet:String? = nil) throws -> (Set<ClientInfo>, String, TimeInterval) {
		try env.transact(readOnly:true) { someTrans -> (Set<ClientInfo>, String, TimeInterval) in
			let clients = try _allClients(tx:someTrans)
			let subnet = try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTrans)!
			let invalidateTime = try self.metadata.getEntry(type:TimeInterval.self, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:someTrans)!
			return (clients, subnet, invalidateTime)
		}
	}
	func validateNewClientName(subnet:String, clientName:String) throws -> Bool {
		try env.transact(readOnly:true) { someTrans -> Bool in
			if try subnetName_networkV6.containsEntry(key:subnet, tx:someTrans) == true {
				let nameCursor = try subnetName_clientNameHash.cursor(tx:someTrans)
				
				let subnetHash = try WiremanD.hash(domain:subnet)
				let clientNameHash = try Self.hash(clientName:clientName)
				if try nameCursor.containsEntry(key:subnetHash, value:clientNameHash) == false {
					return true
				}
			}
			return false
		}
	}
	
	fileprivate func _puntClientInvalidation<K>(to newInvalidationDate:Date? = nil, publicKey:K, tx:Transaction) throws -> Date where K:MDB_encodable {
		// this is the new date that is to be assigned to the client
		let targetDate:Date
		
		if (newInvalidationDate != nil) {
			// if this date was provided by the caller, our work is done
			targetDate = newInvalidationDate!
		} else {
			// the caller did not provide a new invalidation date for this client. we need to take the configured time interval from the metadata database and add it to present time. this is will become the new invalidation date for the client
			let now = Date()
			let shiftTime = try self.metadata.getEntry(type:TimeInterval.self, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:tx)!
			targetDate = now.addingTimeInterval(shiftTime)
		}
		
		// assign the new invalidation date to the client
		try self.clientPub_invalidDate.setEntry(value:targetDate, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:tx)
		
		return targetDate
	}
	
	@discardableResult func puntClientInvalidation(to newInvalidDate:Date? = nil, subnet:String, name:String) throws -> Date {
		let returnDate = try env.transact(readOnly:false) { someTrans in
			let subnetPubsCursor = try self.subnetName_clientPub.cursor(tx:someTrans)
			let clientNameCursor = try self.clientPub_clientName.cursor(tx:someTrans)
			
			// search every client in this subnet for a matching name
			for curKV in try subnetPubsCursor.makeDupIterator(key:subnet) {
				let clientName = String(try clientNameCursor.getEntry(.set, key:curKV.value).value)!
				if (clientName == name) {
					return try self._puntClientInvalidation(to:newInvalidDate, publicKey:curKV.value, tx:someTrans)
				}
			}
			
			throw LMDBError.notFound
		}
		try env.sync()
		return returnDate
	}
	
	@discardableResult func puntAllClients(subnet:String, to newInvalidDate:Date? = nil) throws -> Date {
		let returnVal = try env.transact(readOnly:false) { someTrans in
			let subnetPubsCursor = try self.subnetName_clientPub.cursor(tx:someTrans)
			
			// search every client in this subnet for a matching name
			var puntTo:Date? = newInvalidDate
			for curKV in try subnetPubsCursor.makeDupIterator(key:subnet) {
				puntTo = try self._puntClientInvalidation(to:puntTo, publicKey:curKV.value, tx:someTrans)
			}
			
			guard let didPunt = puntTo else {
				throw LMDBError.notFound
			}
			return didPunt
		}
		try env.sync()
		return returnVal
	}
	
	@discardableResult func puntClientInvalidation(to newInvalidDate:Date? = nil, publicKey:String) throws -> Date {
		let returnVal = try env.transact(readOnly:false) { someTrans in
			try self._puntClientInvalidation(to:newInvalidDate, publicKey:publicKey, tx:someTrans)
		}
		try env.sync()
		return returnVal
	}
	
	func clientRename(publicKey:String, name:String) throws {
		try env.transact(readOnly:false) { someTrans in
			let clientNameCursor = try self.clientPub_clientName.cursor(tx:someTrans)
			let subnetNameClientNameCursor = try self.subnetName_clientNameHash.cursor(tx:someTrans)
			
			// get the current name of the client. this validate that the public key is correct, and also allows us to remove the existing name hash from the subnetName_clientNameHash database
			let getCurrentName = try! clientNameCursor.getEntry(Cursor.Operation.set, key:publicKey).value
			let getCurrentNetworkName = try! self.clientPub_subnetName.getEntry(type:String.self, forKey:publicKey, tx:someTrans)!
			let hashedName = try Self.hash(clientName:getCurrentName)
			
			// replace existing name hash from the database
			try! subnetNameClientNameCursor.getEntry(.getBoth, key:getCurrentNetworkName, value:hashedName)
			try! subnetNameClientNameCursor.deleteEntry()
			let newNameHash = try Self.hash(clientName:name)
			try! subnetNameClientNameCursor.setEntry(value:newNameHash, forKey:getCurrentNetworkName)
			
			try clientNameCursor.setEntry(value:name, forKey:publicKey)
		}
		try env.sync()
	}
	
	
	enum ProcessedHandshakeAction {
		case removeClient(String)
		case resolveIP(String)
	}
	
	func processHandshakes(_ handshakes:[String:Date], endpoints:[String:String], all:Set<String>) throws -> [ProcessedHandshakeAction] {
		return try env.transact(readOnly:false) { someTrans in
			var returnActions = [ProcessedHandshakeAction]()
			let clientHandshakeCursor = try clientPub_handshakeDate.cursor(tx:someTrans)
			let clientInvalidationCursor = try clientPub_invalidDate.cursor(tx:someTrans)
			let clientEndpointCursor = try clientPub_endpointAddress.cursor(tx:someTrans)
			
			let handshakeInvalidationTimeInterval = try metadata.getEntry(type:TimeInterval.self, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:someTrans)!
			
			// any public keys that need to be removed from the wireguard interface are passed into this variable
			var removeKeys = Set<String>()
			
			// iterate through every client with nonzero handshake data
			for curClient in handshakes {
				
				// check if the client exists in the database. client invalidator database is the best database to check for this, since it does not contain the serveres own public key
				do {
					let invalidationDate = Date(try clientInvalidationCursor.getEntry(.set, key:curClient.key).value)!
					do {
						// check the existing handshake
						let existingHandshake = Date(try clientHandshakeCursor.getEntry(.set, key:curClient.key).value)!
						if (existingHandshake < curClient.value) {
							// only update the handshake in the database if the new handshake is a date that is further in time than the existing handshake
							try clientHandshakeCursor.setEntry(value:curClient.value, forKey:curClient.key)
							try clientInvalidationCursor.setEntry(value:curClient.value.addingTimeInterval(handshakeInvalidationTimeInterval), forKey:curClient.key)
							let clientEndpoint = endpoints[curClient.key]!
							try clientEndpointCursor.setEntry(value:clientEndpoint, forKey:curClient.key)
							returnActions.append(.resolveIP(clientEndpoint))
						} else if invalidationDate.timeIntervalSinceNow < 0 {
							// if the client has reached their invalidation period
							try _clientRemove(publicKey:curClient.key, tx:someTrans)
						}
					} catch LMDBError.notFound {
						// this is hte first handshake for this user
						try clientHandshakeCursor.setEntry(value:curClient.value, forKey:curClient.key)
						try clientInvalidationCursor.setEntry(value:curClient.value.addingTimeInterval(handshakeInvalidationTimeInterval), forKey:curClient.key)
						let clientEndpoint = endpoints[curClient.key]!
						try clientEndpointCursor.setEntry(value:clientEndpoint, forKey:curClient.key)
						returnActions.append(.resolveIP(clientEndpoint))
						// remove the webserve config if it exists since we now have proof that the client got the key
						do {
							try webserve__clientPub_configData.deleteEntry(key:curClient.key, tx:someTrans)
						} catch LMDBError.notFound {}
					}
				} catch LMDBError.notFound {
					
					// the client is not in the database so it needs to be removed
					removeKeys.update(with:curClient.key)
					returnActions.append(.removeClient(curClient.key))
				}
			}
			
			let handshakenKeys = Set<String>(handshakes.keys)
			let nonHandshaken = all.subtracting(handshakenKeys)
			for curNonhandshakenClient in nonHandshaken {
				do {
					let invalidationDate = Date(try clientInvalidationCursor.getEntry(.set, key:curNonhandshakenClient).value)!
					if invalidationDate.timeIntervalSinceNow < 0 {
						try _clientRemove(publicKey:curNonhandshakenClient, tx:someTrans)
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

extension WireguardDatabase {
	fileprivate static func hash(clientName:MDB_val) throws -> Data {
		return try Blake2bHasher.hash(clientName, outputLength:32)
	}
	fileprivate static func hash(clientName:String) throws -> Data {
		let stringData = Data(clientName.utf8)
		return try Blake2bHasher.hash(stringData, outputLength:32)
	}
	fileprivate static func generateRandomData() throws -> Data {
		// read 512 bytes of random data from the system
		let randomBuffer = malloc(512);
		defer {
			free(randomBuffer)
		}
		let randomFD = try FileDescriptor.open("/dev/urandom", .readOnly)
		defer {
			close(randomFD.rawValue)
		}
		var totalRead = 0
		repeat {
			totalRead += try randomFD.read(into:UnsafeMutableRawBufferPointer(start:randomBuffer!.advanced(by:totalRead), count:512))
		} while totalRead < 512
		return Data(bytes:randomBuffer!, count:64)
	}
}