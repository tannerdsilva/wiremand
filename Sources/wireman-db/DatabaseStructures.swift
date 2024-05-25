import bedrock
import RAW
import RAW_blake2
import QuickLMDB
import RAW_base64

// represents a public key of a wireguard client. this is the primary UID for the client in the database
@RAW_staticbuff(bytes:32)
@MDB_comparable()
public struct PublicKey:RAW_comparable, Comparable, Hashable, Equatable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(String(RAW_base64.encode(self)))"
	}
}

// represents a pre-shared key for a wireguard client. this is the key that is used to secure the connection between the client and the server
@RAW_staticbuff(bytes:32)
@MDB_comparable()
public struct PresharedKey:RAW_comparable {
	public var debugDescription:String {
		let asString = String(RAW_base64.encode(self))
		let redacted = asString.prefix(8) + "..." + asString.suffix(8)
		return "\(redacted)"
	}
}


@RAW_staticbuff(bytes:32)
@MDB_comparable()
public struct PrivateKey:RAW_comparable, Comparable, Hashable, Equatable, CustomDebugStringConvertible {
	public var debugDescription:String {
		let asString = String(RAW_base64.encode(self))
		let redacted = asString.prefix(4) + "..." + asString.suffix(4)
		return "\(redacted)"
	}
}

// general string
@RAW_convertible_string_type<RAW_byte>(UTF8)
@MDB_comparable()
public struct EncodedString:RAW_comparable, ExpressibleByStringLiteral {}

// client names
@RAW_convertible_string_type<RAW_byte>(UTF8)
@MDB_comparable()
public struct ClientName:RAW_comparable {}

@RAW_staticbuff(bytes:16)
@MDB_comparable()
public struct ClientNameHash:RAW_comparable {
	public init(clientName:ClientName) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(clientName)
		self = try hasher.finish()
	}
}

// subnet names
@RAW_convertible_string_type<RAW_byte>(UTF8)
@MDB_comparable()
public struct SubnetName:RAW_comparable {}

@RAW_staticbuff(bytes:16)
@MDB_comparable()
public struct SubnetNameHash:RAW_comparable {
	public init(subnetName:SubnetName) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(subnetName)
		self = try hasher.finish()
	}
}

@RAW_staticbuff(bytes:128)
@MDB_comparable()
public struct NetworkSecurityKey:RAW_comparable, Comparable, Equatable, Hashable {
	public static func new() throws -> Self {
		return Self(RAW_staticbuff:try readRandomData(size:128))
	}
}
