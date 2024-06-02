import bedrock_ip
import CWireguardTools
import Logging
import bedrock

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

extension Network {
	internal init?(_ aip:Device.Peer.AllowedIPsEntry) {
		if aip.ptr.pointer(to:\.family)!.pointee == AF_INET {
			self = .v4((NetworkV4(address:AddressV4(RAW_staticbuff:&aip.ptr.pointee.ip4), subnetPrefix:aip.ptr.pointer(to:\.cidr)!.pointee)))
		} else if aip.ptr.pointer(to:\.family)!.pointee == AF_INET6 {
			self = .v6((NetworkV6(address:AddressV6(RAW_staticbuff:&aip.ptr.pointee.ip6), subnetPrefix:aip.ptr.pointer(to:\.cidr)!.pointee)))
		} else {
			return nil
		}
	}
}

extension NetworkV4 {
	internal init?(_ aip:Device.Peer.AllowedIPsEntry) {
		guard aip.ptr.pointer(to:\.family)!.pointee == AF_INET else {
			return nil
		}
		let asAddress = AddressV4(RAW_staticbuff:&aip.ptr.pointee.ip4)
		self = NetworkV4(address:asAddress, subnetPrefix:aip.ptr.pointer(to:\.cidr)!.pointee)
	}
}

extension NetworkV6 {
	internal init?(_ aip:Device.Peer.AllowedIPsEntry) {
		guard aip.ptr.pointer(to:\.family)!.pointee == AF_INET6 else {
			return nil
		}
		let asAddress = AddressV6(RAW_staticbuff:&aip.ptr.pointee.ip6)
		self = NetworkV6(address:asAddress, subnetPrefix:aip.ptr.pointer(to:\.cidr)!.pointee)
	}
}

extension Device.Peer {
	public final class AllowedIPsEntry:Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		private static let logger = makeDefaultLogger(label:"Device.Peer.AllowedIPsEntry", logLevel:.trace)
		private var logger = AllowedIPsEntry.logger

	    public var debugDescription:String {
			switch Int32(ptr.pointer(to:\.family)!.pointee) {
			case AF_INET:
				return "AllowedIPsEntry(\"\(String(NetworkV4(self)!.address))/\(ptr.pointer(to:\.cidr)!.pointee)\")"
			case AF_INET6:
				return "AllowedIPsEntry(\"\(String(NetworkV6(self)!.address))/\(ptr.pointer(to:\.cidr)!.pointee)\")"
			default:
				fatalError()
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
		public static func == (lhs:AllowedIPsEntry, rhs:AllowedIPsEntry) -> Bool {
			guard lhs.ptr.pointer(to:\.family)!.pointee == rhs.ptr.pointer(to:\.family)!.pointee else {
				return false
			}
			if lhs.ptr.pointer(to:\.family)!.pointee == AF_INET {
				return NetworkV4(lhs)! == NetworkV4(rhs)!
			} else if lhs.ptr.pointer(to:\.family)!.pointee == AF_INET6 {
				return NetworkV6(lhs)! == NetworkV6(rhs)!
			} else {
				return false
			}
		}
		public static func < (lhs:AllowedIPsEntry, rhs:AllowedIPsEntry) -> Bool {
			switch (Int32(lhs.ptr.pointer(to:\.family)!.pointee), Int32(rhs.ptr.pointer(to:\.family)!.pointee)) {
			case (AF_INET, AF_INET):
				return NetworkV4(lhs)! < NetworkV4(rhs)!
			case (AF_INET6, AF_INET6):
				return NetworkV6(lhs)! < NetworkV6(rhs)!
			case (AF_INET, AF_INET6):
				return true
			case (AF_INET6, AF_INET):
				return false
			default:
				fatalError("unknown values for family")
			}
		}
		public func hash(into hasher:inout Swift.Hasher) {
			switch Int32(ptr.pointer(to:\.family)!.pointee) {
			case AF_INET:
				NetworkV4(self)!.hash(into:&hasher)
			case AF_INET6:
				NetworkV6(self)!.hash(into:&hasher)
			default:
				fatalError("unknown values for family")
			}
		}
	}
}