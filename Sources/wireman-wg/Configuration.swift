import bedrock_ip
import wireman_db
import RAW_blake2

public struct Configuration:Codable {
	public struct TrustedNode:Codable, Hashable, Equatable {
		public let publicKey:PublicKey
		public let presharedKey:PresharedKey
		public var endpoint:AddressV6?	// only ipv6 endpoints are supported with wireman peers for now
	}
	public var privateKey:PrivateKey
	public var trustedNodes:[NetworkV6:Set<TrustedNode>]
	public struct HostedNetwork:Codable, Hashable, Equatable {
		public var interfaceName:String
		public var peerNetwork4:NetworkV4?
		public var peerNetwork6:NetworkV6?
	}
	public var hostedNetworks:Set<HostedNetwork>
}

extension Configuration {
	public static func generateNew() throws -> Self {
		let privateKey = PrivateKey()
		let trustedNodeNetwork = NetworkV6(address:try NetworkV6("fd00::/8")!.randomAddress(), subnetPrefix:96)
		return Self(privateKey:privateKey,trustedNodes:[trustedNodeNetwork:[]], hostedNetworks:[])
	}
}

extension Configuration.TrustedNode {
	public static func generateNew(publicKey:consuming PublicKey, presharedKey:inout PresharedKey?) throws -> Self {
		if (presharedKey == nil) {
			presharedKey = PresharedKey()
		}
		return Self(publicKey:publicKey, presharedKey:presharedKey!, endpoint:nil)
	}

	public func hash(into hasher:inout Swift.Hasher) {
		publicKey.hash(into:&hasher)
	}

	public static func == (lhs:Configuration.TrustedNode, rhs:Configuration.TrustedNode) -> Bool {
		return lhs.publicKey == rhs.publicKey
	}
}