import bedrock
import RAW
import RAW_blake2
import QuickLMDB

// represents a public key of a wireguard client. this is the primary UID for the client in the database
@RAW_staticbuff(bytes:32)
@MDB_comparable()
internal struct PublicKey:RAW_comparable, Comparable, Hashable, Equatable {}

// represents a pre-shared key for a wireguard client. this is the key that is used to secure the connection between the client and the server
@RAW_staticbuff(bytes:32)
@MDB_comparable()
internal struct PresharedKey:RAW_comparable {}

// general string
@RAW_convertible_string_type<RAW_byte>(UTF8)
@MDB_comparable()
internal struct EncodedString:RAW_comparable, ExpressibleByStringLiteral {}

// client names
@RAW_convertible_string_type<RAW_byte>(UTF8)
@MDB_comparable()
internal struct ClientName:RAW_comparable {}

@RAW_staticbuff(bytes:16)
@MDB_comparable()
internal struct ClientNameHash:RAW_comparable {
	public init(clientName:ClientName) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(clientName)
		self = try hasher.finish()
	}
}

// subnet names
@RAW_convertible_string_type<RAW_byte>(UTF8)
@MDB_comparable()
internal struct SubnetName:RAW_comparable {}

@RAW_staticbuff(bytes:16)
@MDB_comparable()
internal struct SubnetNameHash:RAW_comparable {
	public init(subnetName:SubnetName) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(subnetName)
		self = try hasher.finish()
	}
}

@RAW_staticbuff(bytes:128)
@MDB_comparable()
internal struct NetworkSecurityKey:RAW_comparable, Comparable, Equatable, Hashable {
	public static func new() throws -> Self {
		return Self(RAW_staticbuff:try readRandomData(size:128))
	}
}
