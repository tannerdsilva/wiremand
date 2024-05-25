import CWireguardTools
import ArgumentParser
import wireman_db

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

struct Wireguard {
	public final class Device:Hashable, Equatable, Sequence, Sendable {
	    public func makeIterator() -> Iterator {
	        return Iterator(device:self)
	    }

		struct Iterator:IteratorProtocol {
			private var currentPeer:UnsafeMutablePointer<wg_peer>?
			private var currentDevice:Device
			init(device:Device) {
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

	public struct Peer:Hashable, Equatable {
		private let ptr:UnsafeMutablePointer<wg_peer>

		public var publicKey:PublicKey {
			return PublicKey(RAW_staticbuff:&ptr.pointee.public_key)
		}

		public var presharedKey:PresharedKey {
			return PresharedKey(RAW_staticbuff:&ptr.pointee.preshared_key)
		}

		public var persistentKeepalive:UInt16 {
			return ptr.pointee.persistent_keepalive_interval
		}

		fileprivate init(ptr:UnsafeMutablePointer<wg_peer>) {
			self.ptr = ptr
		}

		public static func == (lhs:Peer, rhs:Peer) -> Bool {
			lhs.publicKey == rhs.publicKey
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