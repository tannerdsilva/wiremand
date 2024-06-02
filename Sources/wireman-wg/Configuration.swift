import bedrock_ip
import wireman_db
import RAW_blake2
import RAW

public struct Configuration:Codable, Sendable {
	public struct TrustedNode:Sendable, Codable {
		public var publicKey:PublicKey
		public var presharedKey:PresharedKey
		public struct Endpoint:Sendable, Codable, Hashable, Equatable {
			public var address:Address
			public var port:UInt16
		}
		public var endpoint:Endpoint
		public var allowedIP:AddressV6 // only ipv6 endpoints are supported with wireman peers.
	}
	public struct TrustedNetworkScope:Sendable, Codable {
		public var network:NetworkV6
		public var nodes:Set<TrustedNode>
	}
	public var privateKey:PrivateKey
	public var port:UInt16
	public var trusted:Set<TrustedNetworkScope>
	public var hosted:Set<Network>
}

extension Configuration.TrustedNetworkScope:Hashable, Equatable {
	public static func == (lhs:Self, rhs:Self) -> Bool {
		return lhs.network == rhs.network
	}
	public func hash(into hasher:inout Swift.Hasher) {
		network.hash(into:&hasher)
	}
}


@RAW_staticbuff(bytes:2)
@RAW_staticbuff_fixedwidthinteger_type<UInt16>(bigEndian:true)
fileprivate struct _int16_internal:Sendable {}

extension PublicKey {
	public func computeDefaultEndpointPort() throws -> UInt16 {
		var newHasher = try RAW_blake2.Hasher<B, _int16_internal>(key:self)
		try newHasher.update(Array("default_endpoint_port".utf8))
		let port = (try newHasher.finish().RAW_native() & 0x1FFF)
		return 49152 + port
	}
}

extension Configuration {
	public static func generateNew() throws -> Self {
		let privateKey = PrivateKey()
		let defaultPort = try PublicKey(privateKey:privateKey).computeDefaultEndpointPort()
		return Self(privateKey:privateKey, port:defaultPort, trusted:[], hosted:[])
	}
}

extension Configuration.TrustedNode:Equatable, Hashable {
	public static func generateNew(publicKey:consuming PublicKey, presharedKey:inout PresharedKey?, endpoint:Endpoint, allowedIP:AddressV6) throws -> Self {
		if (presharedKey == nil) {
			presharedKey = PresharedKey()
		}
		return Self(publicKey:publicKey, presharedKey:presharedKey!, endpoint:endpoint, allowedIP:allowedIP)
	}

	public func hash(into hasher:inout Swift.Hasher) {
		publicKey.hash(into:&hasher)
	}

	public static func == (lhs:Configuration.TrustedNode, rhs:Configuration.TrustedNode) -> Bool {
		return lhs.publicKey == rhs.publicKey
	}
}