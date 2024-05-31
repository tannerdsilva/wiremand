import CWireguardTools
import wireman_db
import bedrock
import Logging

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#elseif os(Windows)
import ucrt
#endif

public struct Device:~Copyable {
	public enum Error:Swift.Error {
		case insufficientPermissions
		case internalError
	}

	private static let logger = makeDefaultLogger(label:"Device", logLevel:.trace)
	private var logger = Device.logger
	private let ptr:UnsafeMutablePointer<wg_device>
	private var pending_remove:[PublicKey:Peer]
	private var installed_peers:[PublicKey:Peer]
	public var count:Int {
		get {
			return installed_peers.count
		}
	}

	public mutating func update(with newPeerInfo:Peer) {
		guard newPeerInfo.publicKey != nil else {
			fatalError("cannot update device with peer that has no public key")
		}
		setPeer(peerKey:newPeerInfo.publicKey!, to:newPeerInfo)
	}

	public mutating func remove(_ peer:Peer) {
		guard peer.publicKey != nil else {
			fatalError("cannot remove peer with no public key")
		}
		setPeer(peerKey:peer.publicKey!, to:nil)
	}

	private mutating func setPeer(peerKey:PublicKey, to newValue:Peer?) {
		if newValue != nil {
			newValue!.removeMe = false
			installed_peers[peerKey] = newValue!
			pending_remove.removeValue(forKey:peerKey)
			logger.debug("added peer: '\(peerKey)'")
		} else {
			let wasPreviouslyInstalled = installed_peers.removeValue(forKey:peerKey)
			if wasPreviouslyInstalled == nil {
				logger.info("flagging peer for removal: '\(peerKey)'")
				pending_remove[peerKey] = wasPreviouslyInstalled
				wasPreviouslyInstalled!.removeMe = true
			}
		}
	}

	/// add a new device to the kernel with the specified interface name string.
	/// - parameter name: the name of the device to add
	/// - throws: `Error.insufficientPermissions` if the user does not have permission to add the device
	/// - returns: the new device
	public static func add(name:String) throws -> Device {
		let dev_ptr = wg_add_device(name)
		guard dev_ptr == 0 else {
			throw Error.insufficientPermissions
		}
		var newdev = wg_device()
		strncpy(&newdev.name, name, name.utf8.count)
		newdev.flags = wg_device_flags(rawValue:0)
		let ptr = UnsafeMutablePointer<wg_device>.allocate(capacity:1)
		ptr.initialize(to:newdev)
		return Device(ptr:ptr)
	}

	/// list all of the currently installed wireguard devices on the system.
	public static func list() -> Set<String> {
		let devices:UnsafeMutablePointer<CChar> = wg_list_device_names()
		defer {
			free(devices)
		}

		// validate that the device exists
		var offset = 0
		var buildNames = Set<String>()
		searchLoop: while true {
			let currentName = String(cString:devices.advanced(by:offset))
			guard currentName.isEmpty == false else {
				return buildNames
			}
			buildNames.update(with:currentName)
			offset += currentName.utf8.count + 1 // Move past the current null-terminated string
		}

		return buildNames
	}

	/// loads an existing wireguard interface by name.
	public static func load(name:String) throws -> Device {
		var wgD:UnsafeMutablePointer<wg_device>? = nil
		let startTime = Date()
		let interface = wg_get_device(&wgD, name)
		let endTime = Date()
		logger.debug("load time: \(endTime.timeIntervalSince(startTime))")
		guard interface == 0 else {
			logger.error("failed to load device: '\(name)'")
			throw Error.insufficientPermissions
		}
		guard wgD?.pointee != nil else {
			throw Error.internalError
		}
		return Device(ptr:wgD!)
	}
	
	private init(ptr dev_ptr_in:UnsafeMutablePointer<wg_device>) {
		self.logger[metadataKey:"dev_name"] = "\(String(cString:UnsafeRawPointer(dev_ptr_in).assumingMemoryBound(to:CChar.self)))"
		self.logger[metadataKey:"dev_ifindex"] = "\(dev_ptr_in.pointee.ifindex)"

		// ensure that replace peers is not set, as we will be managing the peers ourselves and not providing access to this flag directly.
		dev_ptr_in.pointer(to:\.flags)!.pointee = wg_device_flags(rawValue:dev_ptr_in.pointer(to:\.flags)!.pointee.rawValue & ~WGDEVICE_REPLACE_PEERS.rawValue)
		
		// capture the peer pointers across the memory layout
		var currentPeer = dev_ptr_in.pointer(to:\.first_peer)!.pointee
		var buildPeerMap = [PublicKey:Peer]()
		while currentPeer != nil {
			defer {
				let oldPeer = currentPeer
				currentPeer = currentPeer?.pointer(to:\.next_peer)!.pointee
				oldPeer!.pointer(to:\.next_peer)!.pointee = nil
			}
			let peer = currentPeer!
			let peerKey = PublicKey(RAW_staticbuff:peer.pointer(to:\.public_key)!)
			buildPeerMap[peerKey] = Peer(peer:peer)
		}
		installed_peers = buildPeerMap
		pending_remove = [:] // no pending removals on init
		ptr = dev_ptr_in

		logger.info("initialized device instance with \(installed_peers.count) peers")
	}

	deinit {
		free(ptr)
		logger.trace("deinitialized instance")
	}

	/// updates the kernel interface to reflect the current state of the device as represented in memory
	public mutating func set() throws {
		ptr.pointer(to:\.first_peer)!.pointee = nil
		var lastPeer:UnsafeMutablePointer<wg_peer>? = nil

		for (_, peer) in installed_peers {
			let exportedPeer = peer.render(as:wg_peer.self)
			defer {
				lastPeer = exportedPeer
			}
			if ptr.pointer(to:\.first_peer)!.pointee == nil {
				ptr.pointer(to:\.first_peer)!.pointee = exportedPeer
			} else {
				lastPeer!.pointer(to:\.next_peer)!.pointee = exportedPeer
			}
		}
		for (_, peer) in pending_remove {
			let exportedPeer = peer.render(as:wg_peer.self)
			defer {
				lastPeer = exportedPeer
			}
			if ptr.pointer(to:\.first_peer)!.pointee == nil {
				ptr.pointer(to:\.first_peer)!.pointee = exportedPeer
			} else {
				lastPeer!.pointer(to:\.next_peer)!.pointee = exportedPeer
			}
		}
		ptr.pointer(to:\.last_peer)!.pointee = lastPeer ?? ptr.pointer(to:\.first_peer)!.pointee
		lastPeer?.pointer(to:\.next_peer)!.pointee = nil
		defer {
			ptr.pointer(to:\.first_peer)!.pointee = nil
			ptr.pointer(to:\.last_peer)!.pointee = nil
		}
		let setDevResult = wg_set_device(ptr)
		logger.info("successfully set device with \(installed_peers.count) peers (\(pending_remove.count) removed)")
		guard setDevResult == 0 else {
			logger.error("failed to set device")
			throw Error.insufficientPermissions
		}
		pending_remove.removeAll()
	}

	public consuming func remove() throws {
		let removeResult = wg_del_device(ptr)
		logger.info("successfully removed device")
		guard removeResult == 0 else {
			logger.error("failed to remove device")
			throw Error.insufficientPermissions
		}
	}
}

extension Device {
    public borrowing func makeIterator() -> Iterator {
		return Iterator(self)
    }

	public struct Iterator:IteratorProtocol {
		public mutating func next() -> [PublicKey:Peer].Element? {
			return iterator.next()
		}

		public typealias Element = [PublicKey:Peer].Element

		private var iterator:[PublicKey:Peer].Iterator
		public init(_ device:borrowing Device) {
			self.iterator = device.installed_peers.makeIterator()
		}
	}
	
	public var interfaceIndex:UInt32 {
		get {
			return ptr.pointer(to:\.ifindex)!.pointee
		}
	}

	public var name:String {
		get {
			return String(cString:UnsafeRawPointer(ptr.pointer(to:\.name)!).assumingMemoryBound(to:CChar.self))
		}
	}

	public var publicKey:PublicKey? {
		get {
			if ptr.pointee.flags.rawValue & WGDEVICE_HAS_PUBLIC_KEY.rawValue != 0 {
				return PublicKey(RAW_staticbuff:ptr.pointer(to:\.public_key)!)
			} else {
				return nil
			}
		}
		set {
			if newValue != nil {
				ptr.pointer(to:\.flags)!.pointee = wg_device_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue | WGDEVICE_HAS_PUBLIC_KEY.rawValue)
				ptr.pointee.public_key = newValue!.RAW_access_staticbuff { 
					return UnsafeRawPointer($0).assumingMemoryBound(to:wg_key.self).pointee
				}
			} else {
				ptr.pointee.flags = wg_device_flags(rawValue:ptr.pointee.flags.rawValue & ~WGDEVICE_HAS_PUBLIC_KEY.rawValue)
			}
		}
	}

	public var privateKey:PrivateKey? {
		get {
			if ptr.pointee.flags.rawValue & WGDEVICE_HAS_PRIVATE_KEY.rawValue != 0 {
				return PrivateKey(RAW_staticbuff:ptr.pointer(to:\.private_key)!)
			} else {
				return nil
			}
		}
		set {
			if newValue != nil {
				ptr.pointer(to:\.flags)!.pointee = wg_device_flags(rawValue:ptr.pointer(to:\.flags)!.pointee.rawValue | WGDEVICE_HAS_PRIVATE_KEY.rawValue)
				ptr.pointee.private_key = newValue!.RAW_access_staticbuff { 
					return UnsafeRawPointer($0).assumingMemoryBound(to:wg_key.self).pointee
				}
			} else {
				ptr.pointee.flags = wg_device_flags(rawValue:ptr.pointee.flags.rawValue & ~WGDEVICE_HAS_PRIVATE_KEY.rawValue)
			}
		}
	}

	public var listeningPort:UInt16? {
		get {
			if ptr.pointee.flags.rawValue & WGDEVICE_HAS_LISTEN_PORT.rawValue != 0 {
				return ptr.pointee.listen_port
			} else {
				return nil
			}
		}
	}
}