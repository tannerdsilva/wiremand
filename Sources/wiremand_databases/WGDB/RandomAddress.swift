import Foundation
import RAW
import bedrock_ip

extension bedrock_ip.NetworkV4 {
	public func randomAddress() throws -> bedrock_ip.AddressV4 {
		let randomBytes = try generateSecureRandomBytes(as: bedrock_ip.AddressV4.self)
		let maskedRandomBytes = ~self.subnetMask & randomBytes
		let result = maskedRandomBytes | (self.subnetMask & self.address)
		return result
	}
}

extension bedrock_ip.NetworkV6 {
	public func randomAddress() throws -> bedrock_ip.AddressV6 {
		let randomBytes = try generateSecureRandomBytes(as: bedrock_ip.AddressV6.self)
		let maskedRandomBytes = ~self.subnetMask & randomBytes
		let result = maskedRandomBytes | (self.subnetMask & self.address)
		return result
	}
}
