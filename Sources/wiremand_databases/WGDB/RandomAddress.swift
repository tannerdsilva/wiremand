import Foundation
import RAW
import bedrock_ip

extension bedrock_ip.NetworkV4 {
	public func randomAddress() throws -> bedrock_ip.AddressV4 {
		let rawRandomBytes = try generateSecureRandomBytes(count: MemoryLayout<bedrock_ip.AddressV4.RAW_fixed_type>.size)
		// the byte count was requested to match the address width exactly, so decode cannot fail.
		let randomBytes = rawRandomBytes.withUnsafeBytes { bedrock_ip.AddressV4(RAW_decode: $0)! }
		let maskedRandomBytes = ~self.subnetMask & randomBytes
		let result = maskedRandomBytes | (self.subnetMask & self.address)
		return result
	}
}

extension bedrock_ip.NetworkV6 {
	public func randomAddress() throws -> bedrock_ip.AddressV6 {
		let rawRandomBytes = try generateSecureRandomBytes(count: MemoryLayout<bedrock_ip.AddressV6.RAW_fixed_type>.size)
		// the byte count was requested to match the address width exactly, so decode cannot fail.
		let randomBytes = rawRandomBytes.withUnsafeBytes { bedrock_ip.AddressV6(RAW_decode: $0)! }
		let maskedRandomBytes = ~self.subnetMask & randomBytes
		let result = maskedRandomBytes | (self.subnetMask & self.address)
		return result
	}
}

extension bedrock_ip.Network {
	public func randomAddress() throws -> bedrock_ip.Address {
		switch self {
			case .v4(let v4):
				return bedrock_ip.Address(String(try v4.randomAddress()))!
			case .v6(let v6):
				return bedrock_ip.Address(String(try v6.randomAddress()))!
		}
	}
}