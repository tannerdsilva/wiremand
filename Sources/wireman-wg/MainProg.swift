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
}

extension PrivateKey {
	public init(interface:UnsafeMutablePointer<wg_device>) {
		self.init(RAW_staticbuff:&interface.pointee.private_key)
	}

	public var publicKey:PublicKey {
		return RAW_access_staticbuff({ (buff:UnsafeRawPointer) in
			let newBuffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<PublicKey.RAW_staticbuff_storetype>.size)
			defer {
				newBuffer.deallocate()
			}
			wg_generate_public_key(newBuffer.baseAddress, buff)
			return PublicKey(RAW_staticbuff:newBuffer.baseAddress!)
		})
	}
}

public struct Wireguard {
	public final class Device:Hashable, Equatable, Sequence, Sendable {
	    public func makeIterator() -> Iterator {
	        return Iterator(device:self)
	    }

		public struct Iterator:IteratorProtocol, Sendable {
			private var currentPeer:UnsafeMutablePointer<wg_peer>?
			private var currentDevice:Device
			
			fileprivate init(device:Device) {
				currentDevice = device
				currentPeer = device.ptr.pointee.first_peer
			}

			public mutating func next() -> Wireguard.Peer? {
				defer {
					currentPeer = currentPeer?.pointee.next_peer
				}
				guard currentPeer != nil else {
					return nil
				}
				return Wireguard.Peer(ptr:currentPeer!)
			}
		}

	    public typealias Element = Peer

		fileprivate let ptr:UnsafeMutablePointer<wg_device>

		public var name:String {
			let tempBuffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:Int(IFNAMSIZ))
			defer {
				tempBuffer.deallocate()
			}
			withUnsafePointer(to:&ptr.pointee) { (ptr:UnsafePointer<wg_device>) in
				withUnsafePointer(to:ptr.pointee.name) {
					_ = memcpy(tempBuffer.baseAddress!, $0, Int(IFNAMSIZ))
				}
			}
			return String(cString:tempBuffer.baseAddress!)
		}

		public var publicKey:PublicKey {
			return PublicKey(RAW_staticbuff:&ptr.pointee.public_key)
		}

		public var listenPort:UInt16? {
			if ptr.pointee.flags.rawValue & WGDEVICE_HAS_LISTEN_PORT.rawValue != 0 {
				return ptr.pointee.listen_port
			} else {
				return nil
			}
		}

		fileprivate var privateKey:PrivateKey {
			return PrivateKey(RAW_staticbuff:&ptr.pointee.private_key)
		}

		fileprivate init(ptr:UnsafeMutablePointer<wg_device>) {
			self.ptr = ptr
		}

		public func update(with insertPeer:Peer) {
			for curPeer in self {
				if curPeer == insertPeer {
					// Update the peer
					return
				}
			}
		}

		public static func load(name:String) throws -> Device {
			return try Wireguard.loadExistingDevice(name:name)
		}

		public static func == (lhs:Device, rhs:Device) -> Bool {
			return lhs.ptr == rhs.ptr
		}

		public func hash(into hasher:inout Hasher) {
			hasher.combine(name)
			hasher.combine(publicKey)
		}

		deinit {
			wg_free_device(ptr)
		}
	}

	public struct Peer:Hashable, Equatable, Sequence {
	    public func makeIterator() -> Iterator {
	        return Iterator(peer:self)
	    }

		public enum AllowedIP {
			case v4(NetworkV4)
			case v6(NetworkV6)

			public init(_ ptr:UnsafeMutablePointer<wg_allowedip>) {
				switch Int32(ptr.pointee.family) {
				case AF_INET:
					let address = AddressV4(RAW_staticbuff:&ptr.pointee.ip4)
					self = .v4(NetworkV4(address:address, prefix:ptr.pointee.cidr))
				case AF_INET6:
					let address = AddressV6(RAW_staticbuff:&ptr.pointee.ip6)
					self = .v6(NetworkV6(address:address, prefix: ptr.pointee.cidr))
				default:
					fatalError("Invalid address family")
				}
			}
		}

		public struct Iterator:IteratorProtocol {
			private var currentAllowedIP:UnsafeMutablePointer<wg_allowedip>?
			private var currentPeer:Peer

			fileprivate init(peer:Peer) {
				currentPeer = peer
				currentAllowedIP = peer.ptr.pointee.first_allowedip
			}

			public mutating func next() -> AllowedIP? {
				defer {
					currentAllowedIP = currentAllowedIP?.pointee.next_allowedip
				}
				guard currentAllowedIP != nil else {
					return nil
				}
				return AllowedIP(currentAllowedIP!)
			}
		}

		private let ptr:UnsafeMutablePointer<wg_peer>

		public var publicKey:PublicKey {
			return PublicKey(RAW_staticbuff:&ptr.pointee.public_key)
		}

		public var presharedKey:PresharedKey? {
			guard ptr.pointee.flags.rawValue & WGPEER_HAS_PRESHARED_KEY.rawValue != 0 else {
				return nil
			}
			return PresharedKey(RAW_staticbuff:&ptr.pointee.preshared_key)
		}


		fileprivate init(ptr:UnsafeMutablePointer<wg_peer>) {
			self.ptr = ptr
		}

		public static func == (lhs:Peer, rhs:Peer) -> Bool {
			lhs.publicKey == rhs.publicKey
		}

		public func hash(into hasher:inout Hasher) {
			hasher.combine(publicKey)
		}

		public func apply(to location:UnsafeMutablePointer<wg_peer>) {
			memcpy(location, ptr, MemoryLayout<wg_peer>.size)
		}
		
	}


	public enum Error:Swift.Error {
		case interfaceNotFound
		case insufficientPermissions
		case internalError
	}

	internal static func createPrivateKey() -> PrivateKey {
		let pkBytes = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<PrivateKey.RAW_staticbuff_storetype>.size)
		defer {
			pkBytes.deallocate()
		}
		wg_generate_private_key(pkBytes.baseAddress)
		return PrivateKey(RAW_staticbuff:pkBytes.baseAddress!)
	}

	internal static func createPresharedKey() -> PresharedKey {
		let pkBytes = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<PresharedKey.RAW_staticbuff_storetype>.size)
		defer {
			pkBytes.deallocate()
		}
		wg_generate_preshared_key(pkBytes.baseAddress)
		return PresharedKey(RAW_staticbuff:pkBytes.baseAddress!)
	}

	/// loads an existing wireguard interface by name.
	/// - parameter name: the name of the interface to load
	/// - throws: `Error.interfaceNotFound` if the interface does not exist
	/// - throws: `Error.insufficientPermissions` if the user does not have permission to access the interface
	/// - throws: `Error.internalError` if the interface could not be loaded for an unknown reason (this should not happen)
	internal static func loadExistingDevice(name:String) throws -> Device {
		let devices:UnsafeMutablePointer<CChar> = wg_list_device_names()
		defer {
			free(devices)
		}

		// validate that the device exists
		var offset = 0
		searchLoop: while true {
			let currentName = String(cString:devices.advanced(by:offset))
			guard currentName.isEmpty == false else {
				throw Error.interfaceNotFound
			}
			guard currentName != name else {
				break searchLoop
			}
			offset += currentName.utf8.count + 1 // Move past the current null-terminated string
		}

		var wgd:UnsafeMutablePointer<wg_device>? = nil
		let interface = wg_get_device(&wgd, name)
		guard interface == 0 else {
			throw Error.insufficientPermissions
		}
		guard wgd?.pointee != nil else {
			throw Error.internalError
		}
		return Device(ptr:wgd!)
	}

	public static func createDevice(name newName:String) throws {
		var newDevice = wg_device()
		memcpy(&newDevice.name, newName, newName.count)
		newDevice.flags = WGDEVICE_HAS_PRIVATE_KEY
		wg_generate_private_key(&newDevice.private_key)
		let addDevResult = wg_add_device(&newDevice)
		guard addDevResult == 0 else {
			throw Error.insufficientPermissions
		}
		let sedDevResult = wg_set_device(&newDevice)
		guard sedDevResult == 0 else {
			throw Error.internalError
		}
	}
}


@main
struct InitializeInterface:AsyncParsableCommand {
	@Argument(help:"The name of the wireguard interface to manage")
	var interfaceName:String

	mutating func run() throws {
		let wireguardInterface:Wireguard.Device
		do {
			wireguardInterface = try Wireguard.Device.load(name:interfaceName)
		} catch Wireguard.Error.interfaceNotFound {
			try Wireguard.createDevice(name:interfaceName)
			wireguardInterface = try Wireguard.Device.load(name:interfaceName)
		}
		let intPK = wireguardInterface.publicKey
		print("Interface Public Key: \(intPK)")
	}
}

extension Wireguard.Peer.AllowedIP:Hashable, Equatable {

			public static func == (lhs:Wireguard.Peer.AllowedIP, rhs:Wireguard.Peer.AllowedIP) -> Bool {
				switch (lhs, rhs) {
				case (.v4(let a), .v4(let b)):
					return a == b
				case (.v6(let a), .v6(let b)):
					return a == b
				default:
					return false
				}
			}

			public func hash(into hasher:inout Hasher) {
				switch self {
				case .v4(let a):
					hasher.combine("v4")
					hasher.combine(a)
				case .v6(let a):
					hasher.combine("v6")
					hasher.combine(a)
				}
			}

}