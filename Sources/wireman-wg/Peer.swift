import CWireguardTools
import wireman_db
import Logging
import bedrock_ip
import bedrock

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

extension Device {
	public final class Peer:Sequence, Hashable, Equatable {
		private static let logger = makeDefaultLogger(label:"Device.Peer", logLevel:.trace)
		private var logger = Peer.logger

		public typealias Element = AllowedIPsEntry
		public typealias Iterator = Set<AllowedIPsEntry>.Iterator
		public func makeIterator() -> Set<AllowedIPsEntry>.Iterator {
			return allowedIPs.makeIterator()
		}
		
		private let ptr:UnsafeMutablePointer<wg_peer>
		private var allowedIPs:Set<AllowedIPsEntry>

		/// will be true if the peer flags indicate that the peer is marked for removal
		internal var removeMe:Bool {
			get {
				return (ptr.pointer(to:\.flags)!.pointee.rawValue & WGPEER_REMOVE_ME.rawValue) == 0
			}
			set {
				if newValue {
					ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue | WGPEER_REMOVE_ME.rawValue)
				} else {
					ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue & ~WGPEER_REMOVE_ME.rawValue)
				}
			}
		}

		/// the public key of the peer
		public var publicKey:PublicKey? {
			get {
				guard ptr.pointer(to:\.flags)!.pointee.rawValue & WGPEER_HAS_PUBLIC_KEY.rawValue != 0 else {
					return nil
				}
				return PublicKey(RAW_staticbuff:ptr.pointer(to:\.public_key)!)
			}
			set {
				if newValue != nil {
					ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue | WGPEER_HAS_PUBLIC_KEY.rawValue)
					ptr.pointer(to:\.public_key)!.pointee = newValue!.RAW_access_staticbuff({
						return $0.assumingMemoryBound(to:wg_key.self).pointee
					})
				} else {
					ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue & ~WGPEER_HAS_PUBLIC_KEY.rawValue)
				}
			}
		}

		/// the preshared key of the peer
		public var presharedKey:PresharedKey? {
			get {
				guard ptr.pointer(to:\.flags)!.pointee.rawValue & WGPEER_HAS_PRESHARED_KEY.rawValue != 0 else {
					return nil
				}
				return PresharedKey(RAW_staticbuff:ptr.pointer(to:\.preshared_key)!)
			}
			set {
				if newValue != nil {
					ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue | WGPEER_HAS_PRESHARED_KEY.rawValue)
					ptr.pointer(to:\.preshared_key)!.pointee = newValue!.RAW_access_staticbuff({
						return $0.assumingMemoryBound(to:wg_key.self).pointee
					})
				} else {
					ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue & ~WGPEER_HAS_PRESHARED_KEY.rawValue)
				}
			}
		}

		public var latestHandshake:bedrock.Date {
			get {
				let timespec = ptr.pointer(to:\.last_handshake_time)!.pointee
				let doubleVal = Double(timespec.tv_sec) + Double(timespec.tv_nsec) / 1_000_000_000
				return bedrock.Date(unixInterval:doubleVal)
			}
		}

		public var endpoint:Endpoint? {
			get {
				if ptr.pointer(to:\.endpoint)!.pointee.addr.sa_family != 0 {
					return Endpoint(ptr.pointer(to:\.endpoint)!)
				} else {
					return nil
				}
			}
			set {
				if newValue != nil {
					newValue!.encode(to:ptr.pointer(to:\.endpoint)!)
				} else {
					ptr.pointer(to:\.endpoint)!.pointee.addr.sa_family = 0
				}
			}
		}

		
		internal init(peer:UnsafeMutablePointer<wg_peer>) {
			#if DEBUG
			guard peer.pointer(to:\.flags)!.pointee.rawValue & WGPEER_REMOVE_ME.rawValue == 0 else {
				fatalError("peer cannot be initialized if it is marked for removal")
			}
			#endif

			guard peer.pointer(to:\.flags)!.pointee.rawValue & WGPEER_HAS_PUBLIC_KEY.rawValue != 0 else {
				fatalError("peer must have a public key")
			}

			ptr = peer
			var currentAllowedIP = peer.pointer(to:\.first_allowedip)!.pointee
			var buildEntries = Set<AllowedIPsEntry>()
			while currentAllowedIP != nil {
				defer {
					let oldAllowedIP = currentAllowedIP
					currentAllowedIP = currentAllowedIP?.pointee.next_allowedip
					oldAllowedIP!.pointee.next_allowedip = nil
				}
				let allowedIPEntry = AllowedIPsEntry(ptr:currentAllowedIP!)
				buildEntries.update(with:allowedIPEntry)
			}
			allowedIPs = buildEntries

			logger[metadataKey:"publicKey"] = "\(publicKey!)"
		}

		internal init(publicKey:PublicKey, presharedKey:PresharedKey?) {
			ptr = UnsafeMutablePointer<wg_peer>.allocate(capacity:1)
			ptr.initialize(to:wg_peer())
			ptr.pointer(to:\.flags)!.pointee = WGPEER_HAS_PUBLIC_KEY
			ptr.pointer(to:\.public_key)!.pointee = publicKey.RAW_access_staticbuff({
				return $0.assumingMemoryBound(to:wg_key.self).pointee
			})
			if presharedKey != nil {
				ptr.pointer(to:\.flags)!.pointee = wg_peer_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue | WGPEER_HAS_PRESHARED_KEY.rawValue)
				ptr.pointer(to:\.preshared_key)!.pointee = presharedKey!.RAW_access_staticbuff({
					return $0.assumingMemoryBound(to:wg_key.self).pointee
				})
			}
			allowedIPs = []

			logger[metadataKey:"publicKey"] = "\(publicKey)"
		}

		internal func render(as _:wg_peer.Type) -> UnsafeMutablePointer<wg_peer> {
			ptr.pointer(to:\.first_allowedip)!.pointee = nil
			var lastAllowedIP:UnsafeMutablePointer<wg_allowedip>? = nil
			for allowedIP in allowedIPs {
				defer {
					lastAllowedIP = allowedIP.ptr
				}
				if ptr.pointer(to:\.first_allowedip)!.pointee == nil {
					ptr.pointer(to:\.first_allowedip)!.pointee = allowedIP.ptr
				} else {
					ptr.pointer(to:\.last_allowedip)!.pointee = allowedIP.ptr
				}
			}
			ptr.pointer(to:\.last_allowedip)!.pointee = lastAllowedIP ?? ptr.pointer(to:\.first_allowedip)!.pointee
			lastAllowedIP?.pointer(to:\.next_allowedip)?.pointee = nil
			return ptr
		}

		public func update(with allowIP:AllowedIPsEntry) {
			logger.debug("updating allowed IPs with \(allowIP)")
			allowedIPs.update(with:allowIP)
		}

		public func remove(_ allowIP:AllowedIPsEntry) {
			logger.debug("removing allowed IPs with \(allowIP)")
			allowedIPs.remove(allowIP)
		}

		public static func == (lhs:Peer, rhs:Peer) -> Bool {
			return lhs.publicKey == rhs.publicKey
		}

		public func hash(into hasher:inout Hasher) {
			hasher.combine(publicKey)
		}

		deinit {
			logger.trace("deinitialized instance")
			free(ptr)
		}
	}
}


extension Device {
	public enum Endpoint {
		case v4(AddressV4, UInt16)
		case v6(AddressV6, UInt16)
		public init?(_ ptr:UnsafePointer<wg_endpoint>) {
			switch Int32(ptr.pointer(to:\.addr)!.pointer(to:\.sa_family)!.pointee) {
			case AF_INET:
				let address = AddressV4(RAW_staticbuff:ptr.pointer(to:\.addr4)!.pointer(to:\.sin_addr)!)
				self = .v4(address, ptr.pointer(to: \.addr4)!.pointer(to:\.sin_port)!.pointee)
			case AF_INET6:
				let address = AddressV6(RAW_staticbuff:ptr.pointer(to:\.addr6)!.pointer(to:\.sin6_addr)!)
				self = .v6(address, ptr.pointer(to:\.addr6)!.pointer(to:\.sin6_port)!.pointee)
			default:
				return nil
			}
		}

		public var port:UInt16 { 
			get {
				switch self {
					case let .v4(_, port): return port
					case let .v6(_, port): return port
				}
			}
		}

		public func isIPv4() -> Bool {
			switch self {
				case .v4: return true
				case .v6: return false
			}
		}

		public func addressV4() -> AddressV4? {
			switch self {
				case let .v4(address, _): return address
				case .v6: return nil
			}
		}

		public func addressV6() -> AddressV6? {
			switch self {
				case let .v6(address, _): return address
				case .v4: return nil
			}
		}

		public func isIPv6() -> Bool {
			return !isIPv4()
		}

		fileprivate func encode(to destEndpoint:UnsafeMutablePointer<wg_endpoint>) {
			switch self {
				case let .v4(address, port):
					destEndpoint.pointer(to:\.addr)!.pointee.sa_family = sa_family_t(AF_INET)
					destEndpoint.pointer(to:\.addr4)!.pointee.sin_addr = address.RAW_access_staticbuff({
						return $0.assumingMemoryBound(to:in_addr.self).pointee
					})
					destEndpoint.pointer(to:\.addr4)!.pointee.sin_port = port
				case let .v6(address, port):
					destEndpoint.pointer(to:\.addr)!.pointee.sa_family = sa_family_t(AF_INET6)
					destEndpoint.pointer(to:\.addr6)!.pointee.sin6_addr = address.RAW_access_staticbuff({
						return $0.assumingMemoryBound(to:in6_addr.self).pointee
					})
					destEndpoint.pointer(to:\.addr6)!.pointee.sin6_port = port
			}
		}
	}
}