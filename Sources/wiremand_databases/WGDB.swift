import QuickLMDB
import RAW
import RAW_dh25519
import RAW_blake2
import bedrock_ip
import bedrock
import RAW_base64

@RAW_staticbuff(concat:RAW_dh25519.PublicKey.self)
@MDB_comparable
public struct PublicKey:Sendable {
	fileprivate let pk:RAW_dh25519.PublicKey
}

@RAW_staticbuff(concat:bedrock_ip.AddressV4.self)
@MDB_comparable
public struct AddressV4:Sendable {
	fileprivate let addr:bedrock_ip.AddressV4
	internal init(_ addrIn:bedrock_ip.AddressV4) {
		addr = addrIn
	}
}

@RAW_staticbuff(concat:bedrock_ip.NetworkV4.self)
@MDB_comparable
public struct NetworkV4:Sendable {
	fileprivate let net:bedrock_ip.NetworkV4
	internal init(_ netIn:bedrock_ip.NetworkV4) {
		net = netIn
	}
}

@RAW_staticbuff(concat:bedrock_ip.AddressV6.self)
@MDB_comparable
public struct AddressV6:Sendable {
	fileprivate let addr:bedrock_ip.AddressV6
	internal init(_ addrIn:bedrock_ip.AddressV6) {
		addr = addrIn
	}
}

@RAW_staticbuff(concat:bedrock_ip.NetworkV6.self)
@MDB_comparable
public struct NetworkV6:Sendable {
	fileprivate let net:bedrock_ip.NetworkV6
	internal init(_ netIn:bedrock_ip.NetworkV6) {
		net = netIn
	}
}

@RAW_convertible_string_type<UTF8>(backing:RAW_byte.self)
@MDB_comparable
public struct EncodedString:Sendable {}

@RAW_staticbuff(bytes:8)
@MDB_comparable
public struct SubnetHash:Sendable {
	public init(subnetName:EncodedString) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(subnetName)
		self = try hasher.finish()
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
}

public struct WireguardDatabase_vX {
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

		// Client Databases
		/// Maps a client public key to their respective ipv4 address assignment (intended for small uses)
		case clientPub_ipv4 = "pub_4"	//String:AddressV4
		/// Maps a client ipv4 address assignment to their respective public key (intended for infrequent uses)
		case ipv4_clientPub = "4_pub"	//AddressV4:String
		/// Maps a client public key to their respective ipv6 address assignment
		case clientPub_ipv6 = "pub_6" //String:AddressV6
		// Maps a client ipv6 address to their public key
		case ipv6_clientPub = "6_pub" //AddressV6:String
		/// Maps a client public key to their respective client name
		case clientPub_clientName = "pub_name" //String:String
		/// Maps a client public key to their keys respective creation date
		case clientPub_createdOn = "pub_createDate" //String:Date
		/// Maps a client public key to their respective subnet
		case subnetNameHash_subnetName = "subnetNameHash_subnetName" //String:String
		/// Maps a client public key to their respective subnet name hash
		case clientPub_subnetNameHash = "pub_subnetNameHash" //String:SubnetHash
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
	let clientPub_ipv4:Database.Strict<PublicKey, AddressV4>
	let ipv4_clientPub:Database.Strict<AddressV4, PublicKey>
	
	// - required ipv6 related databases
	let clientPub_ipv6:Database.Strict<PublicKey, AddressV6>
	let ipv6_clientPub:Database.Strict<AddressV6, PublicKey>
	
	// - required client info
	let clientPub_clientName:Database.Strict<PublicKey, EncodedString>
	let clientPub_createdOn:Database.Strict<PublicKey, Date.Seconds>

	// - required subnet info
	let subnetNameHash_subnetName:Database.Strict<SubnetHash, EncodedString>
	let clientPub_subnetNameHash:Database.Strict<PublicKey, SubnetHash>
	
	// - optional metadata about the client that is captured when the client connects to the network. this is not required for the client to be considered "valid" and "functional" in the system
	let clientPub_handshakeDate:Database.Strict<PublicKey, Date.Seconds>
	let clientPub_endpointAddress:Database.Strict<PublicKey, Address>
	
	// - if the client is configured to be auto revoked, this is the date that it will be revoked.
	// 	- note: this database is only valid for clients that have connected to the network at least once. if a client has never connected to the network, it will not have a valid entry in this database, and any auto 
	let clientPub_invalidDate:Database.Strict<PublicKey, Date.Seconds>
	
	// subnet info
	/*let subnetName_networkV6:Database.Strict<EncodedString, Network>
	let networkV6_subnetName:Database.Strict<NetworkV6, EncodedString>
	let subnetHash_securityKey:Database.Strict<SubnetHash, EncodedString>
	
	// subnet + client info
	let subnetName_clientPub:Database.Strict<EncodedString, PublicKey>
	let subnetName_clientNameHash:Database.Strict<EncodedString, ClientNameHash>*/


}