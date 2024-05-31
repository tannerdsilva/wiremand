import CWireguardTools
import ArgumentParser
import wireman_db
import bedrock_ip

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

extension PublicKey {
	public init(interface:UnsafeMutablePointer<wg_device>) {
		self.init(RAW_staticbuff:&interface.pointee.public_key)
	}
}

extension PrivateKey {
	public init(interface:UnsafeMutablePointer<wg_device>) {
		self.init(RAW_staticbuff:&interface.pointee.private_key)
	}
}