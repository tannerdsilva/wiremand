import CWireguardTools
import ArgumentParser
import wireman_db
import bedrock_ipaddress

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

extension PublicKey {
	public init(interface:UnsafeMutablePointer<wg_device>) {
		self.init(RAW_staticbuff:&interface.pointee.public_key)
	}

	public init(_ pk:borrowing PrivateKey) {
		self = pk.RAW_access_staticbuff({ (buff:UnsafeRawPointer) in
			let newBuffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<PublicKey.RAW_staticbuff_storetype>.size)
			defer {
				newBuffer.deallocate()
			}
			wg_generate_public_key(newBuffer.baseAddress, buff)
			return PublicKey(RAW_decode:newBuffer.baseAddress!, count:MemoryLayout<PublicKey.RAW_staticbuff_storetype>.size)!
		})
	}
}

extension PrivateKey {
	public init(interface:UnsafeMutablePointer<wg_device>) {
		self.init(RAW_staticbuff:&interface.pointee.private_key)
	}

	public static func random() -> PrivateKey {
		let newBuffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<PrivateKey.RAW_staticbuff_storetype>.size)
		defer {
			newBuffer.deallocate()
		}
		wg_generate_private_key(newBuffer.baseAddress)
		return PrivateKey(RAW_decode:newBuffer.baseAddress!, count:MemoryLayout<PrivateKey.RAW_staticbuff_storetype>.size)!
	}
}

extension PresharedKey {
	public static func random() -> PresharedKey {
		let newBuffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<PresharedKey.RAW_staticbuff_storetype>.size)
		defer {
			newBuffer.deallocate()
		}
		wg_generate_preshared_key(newBuffer.baseAddress)
		return PresharedKey(RAW_decode:newBuffer.baseAddress!, count:MemoryLayout<PresharedKey.RAW_staticbuff_storetype>.size)!
	}
}
