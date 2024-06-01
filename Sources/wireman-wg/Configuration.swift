import bedrock_ip
import wireman_db
import RAW_blake2

public struct Configuration:Codable, Sendable {
	public struct TrustedNode:Sendable, Codable, Hashable, Equatable {
		public var publicKey:PublicKey
		public var presharedKey:PresharedKey
		public struct Endpoint:Sendable, Codable, Hashable, Equatable {
			public var address:Address
			public var port:UInt16
		}
		public var endpoint:Endpoint
		public var allowedIP:AddressV6 // only ipv6 endpoints are supported with wireman peers.
	}
	public var privateKey:PrivateKey
	public var port:UInt16
	public var trustedNodes:[NetworkV6:Set<TrustedNode>]
	public var hostedNetworks:Set<Network>
}

extension Configuration {
	public static func generateNew() throws -> Self {
		let privateKey = PrivateKey()
		return Self(privateKey:privateKey, port:UInt16.random(in: 49152...65535), trustedNodes:[:], hostedNetworks:[])
	}
}

extension Configuration.TrustedNode {
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