import bedrock_ip
import CWireguardTools
import Logging
import bedrock

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

extension Device.Peer {
	public final class AllowedIPsEntry:Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		private static let logger = makeDefaultLogger(label:"Device.Peer.AllowedIPsEntry", logLevel:.trace)
		private var logger = AllowedIPsEntry.logger

	    public var debugDescription:String {
			switch (isIPv4()) {
			case true:
				return "AllowedIPsEntry(\"\(String(addressV4()!))/\(ptr.pointer(to:\.cidr)!.pointee)\")"
			case false:
				return "AllowedIPsEntry(\"\(String(addressV6()!))/\(ptr.pointer(to:\.cidr)!.pointee)\")"
			}
		}

		internal let ptr:UnsafeMutablePointer<wg_allowedip>
		internal convenience init(_ net:Network) {
			switch net {
			case .v4(let av4):
				self.init(av4)
			case .v6(let av6):
				self.init(av6)
			}
		}
		internal init(_ av6:NetworkV6) {
			var allowedIP = wg_allowedip()
			allowedIP.family = UInt16(AF_INET6)
			allowedIP.cidr = av6.subnetPrefix
			allowedIP.ip6 = av6.RAW_access_staticbuff {
				return $0.assumingMemoryBound(to:in6_addr.self).pointee
			}
			let ptr = UnsafeMutablePointer<wg_allowedip>.allocate(capacity:1)
			ptr.initialize(to:allowedIP)
			self.ptr = ptr
		}
		internal init(_ av4:NetworkV4) {
			var allowedIP = wg_allowedip()
			allowedIP.family = UInt16(AF_INET)
			allowedIP.cidr = av4.subnetPrefix
			withUnsafeMutablePointer(to:&allowedIP.ip4) { (dest:UnsafeMutablePointer<in_addr>) in
				_ = av4.RAW_encode(dest:UnsafeMutableRawPointer(dest).assumingMemoryBound(to:UInt8.self))
			}
			let ptr = UnsafeMutablePointer<wg_allowedip>.allocate(capacity:1)
			ptr.initialize(to:allowedIP)
			self.ptr = ptr
		}
		internal init(ptr:UnsafeMutablePointer<wg_allowedip>) {
			self.ptr = ptr
		}
		deinit {
			logger.trace("deinitialized instance")
			free(ptr)
		}
		public static func == (lhs:borrowing AllowedIPsEntry, rhs:borrowing AllowedIPsEntry) -> Bool {
			switch (lhs.isIPv4(), rhs.isIPv4()) {
			case (true, true):
				return lhs.addressV4() == rhs.addressV4() && lhs.ptr.pointer(to:\.cidr)!.pointee == rhs.ptr.pointer(to:\.cidr)!.pointee
			case (false, false):
				return lhs.addressV6() == rhs.addressV6() && lhs.ptr.pointer(to:\.cidr)!.pointee == rhs.ptr.pointer(to:\.cidr)!.pointee
				default:
				return false
			}
		}
		public static func < (lhs:borrowing AllowedIPsEntry, rhs:borrowing AllowedIPsEntry) -> Bool {
			switch (lhs.isIPv4(), rhs.isIPv4()) {
			case (true, true):
				return lhs.addressV4()! < rhs.addressV4()!
			case (false, false):
				return lhs.addressV6()! < rhs.addressV6()!
			default:
				return false
			}
		}
		public func hash(into hasher:inout Swift.Hasher) {
			switch (isIPv4()) {
			case true:
				hasher.combine("4")
				hasher.combine(addressV4())
				hasher.combine(ptr.pointer(to:\.cidr)!.pointee)
			case false:
				hasher.combine("6")
				hasher.combine(addressV6())
				hasher.combine(ptr.pointer(to:\.cidr)!.pointee)
			}
		}
		private borrowing func isIPv4() -> Bool {
			return Int32(ptr.pointee.family) == AF_INET
		}
		private borrowing func addressV4() -> AddressV4? {
			guard Int32(ptr.pointer(to:\.family)!.pointee) == AF_INET else {
				return nil
			}
			return AddressV4(RAW_decode:&ptr.pointee.ip4, count:MemoryLayout<in_addr>.size)
		}
		private borrowing func isIPv6() -> Bool {
			return Int32(ptr.pointee.family) == AF_INET6
		}
		private borrowing func addressV6() -> AddressV6? {
			guard Int32(ptr.pointer(to:\.family)!.pointee) == AF_INET6 else {
				return nil
			}
			return AddressV6(RAW_decode:&ptr.pointee.ip6, count:MemoryLayout<in6_addr>.size)
		}
	}
}