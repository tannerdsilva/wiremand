import bedrock
import RAW
import RAW_blake2
import QuickLMDB
import RAW_base64
import CWireguardTools

// represents a public key of a wireguard client. this is the primary UID for the client in the database
@RAW_staticbuff(bytes:32)
@MDB_comparable()
public struct PublicKey:RAW_comparable, Comparable, Hashable, Equatable, CustomDebugStringConvertible, Codable {
	public init(privateKey:borrowing PrivateKey) {
		var newSbuf:RAW_staticbuff_storetype = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		privateKey.RAW_access_staticbuff { (sbuf) in
			wg_generate_public_key(&newSbuf, sbuf)
		}
		self = .init(RAW_staticbuff:&newSbuf)
	}

	public init?(_ description: String) {
		do {
			let decoded = try RAW_base64.decode(description)
			self = .init(RAW_staticbuff:decoded)
		} catch {
			return nil
		}
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		let string = try container.decode(String.self)
		guard let data = try? RAW_base64.decode(string) else {
			throw DecodingError.dataCorruptedError(in:container, debugDescription:"Invalid base64")
		}
		self = .init(RAW_staticbuff:data)
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(String(RAW_base64.encode(self)))
	}

	public var debugDescription:String {
		return "PublicKey(\"\(String(RAW_base64.encode(self)))\")"
	}
}

@RAW_staticbuff(bytes:32)
@MDB_comparable()
public struct PresharedKey:RAW_comparable, Comparable, Hashable, Equatable, CustomDebugStringConvertible, Codable {
	public init() {
		var sbuf:RAW_staticbuff_storetype = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		withUnsafeMutablePointer(to:&sbuf) { (sbufPtr) in
			wg_generate_preshared_key(sbufPtr)
		}
		self = .init(RAW_staticbuff:&sbuf)
	}
	
	public init(from decoder:Decoder) throws {
		let container = try decoder.singleValueContainer()
		let string = try container.decode(String.self)
		do {
			let data = try RAW_base64.decode(string)
			self = .init(RAW_staticbuff:data)
		} catch {
			throw DecodingError.dataCorruptedError(in:container, debugDescription:"Invalid base64")
		}
	}

	public func encode(to encoder:Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(String(RAW_base64.encode(self)))
	}

    public init?(_ description: String) {
		do {
			let decoded = try RAW_base64.decode(description)
			self = .init(RAW_staticbuff:decoded)
		} catch {
			return nil
		}
    }

	public var debugDescription:String {
		return "PresharedKey(\"\(String(RAW_base64.encode(self)))\")"
	}
}


@RAW_staticbuff(bytes:32)
@MDB_comparable()
public struct PrivateKey:RAW_comparable, Comparable, Hashable, Equatable, CustomDebugStringConvertible, Codable {
    public init() {
		var sbuf:RAW_staticbuff_storetype = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		withUnsafeMutablePointer(to:&sbuf) { (sbufPtr) in
			wg_generate_private_key(sbufPtr)
		}
		self = .init(RAW_staticbuff:&sbuf)
	}
	public init(from decoder:Decoder) throws {
		let container = try decoder.singleValueContainer()
		let string = try container.decode(String.self)
		do {
			let data = try RAW_base64.decode(string)
			self = .init(RAW_staticbuff:data)
		} catch {
			throw DecodingError.dataCorruptedError(in:container, debugDescription:"Invalid base64")
		}
	}

	public func encode(to encoder:Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(String(RAW_base64.encode(self)))
	}
	
	public init?(_ description:String) {
		guard let data = try? RAW_base64.decode(description) else {
			return nil
		}
		self = .init(RAW_staticbuff:data)
    }

	public var debugDescription:String {
		let asString = String(RAW_base64.encode(self))
		let redacted = asString.prefix(4) + "..." + asString.suffix(4)
		return "PrivateKey(\"\(redacted)\")"
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
