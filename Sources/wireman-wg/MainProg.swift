
import CWireguardTools
import ArgumentParser
import wireman_db
import bedrock_ipaddress
import wireman_rtnetlink

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

// extension wg_allowedip {
// 	public init(_ allowedIP:Wireguard.Device.Pe.AllowedIPsEntry) {
// 		self.init()
// 		switch allowedIP.isIPv4() {
// 		case true:
// 			let v4 = allowedIP.addressV4()!
// 			family = UInt16(AF_INET)
// 			cidr = v4.prefix
// 			v4.address.RAW_access_staticbuff { (addr:UnsafeRawPointer) in
// 				_ = memcpy(&ip4, addr, MemoryLayout<in_addr>.size)
// 			}
// 			next_allowedip = nil
// 		case false:
// 			let v6 = allowedIP.addressV6()!
// 			family = UInt16(AF_INET6)
// 			cidr = v6.prefix
// 			v6.address.RAW_access_staticbuff { (addr:UnsafeRawPointer) in
// 				_ = memcpy(&ip6, addr, MemoryLayout<in6_addr>.size)
// 			}
// 			next_allowedip = nil
// 		}
// 	}
// }

extension Device {
	public final class Peer {
		private let ptr:UnsafeMutablePointer<wg_peer>

		internal var removeMe:Bool {
			get {
				return (ptr.pointer(to:\.flags)!.pointee.rawValue & WGPEER_REMOVE_ME.rawValue) == 0
			}
		}

		private var allowedIPs:Set<AllowedIPsEntry>
		private final class AllowedIPsEntry:Hashable, Equatable {
			internal let ptr:UnsafeMutablePointer<wg_allowedip>
			internal init(ptr:UnsafeMutablePointer<wg_allowedip>) {
				self.ptr = ptr
			}
			deinit {
				free(ptr)
			}
			internal static func == (lhs:borrowing AllowedIPsEntry, rhs:borrowing AllowedIPsEntry) -> Bool {
				switch (lhs.isIPv4(), rhs.isIPv4()) {
				case (true, true):
					return lhs.addressV4() == rhs.addressV4() && lhs.ptr.pointer(to:\.cidr)!.pointee == rhs.ptr.pointer(to:\.cidr)!.pointee
				case (false, false):
					return lhs.addressV6() == rhs.addressV6() && lhs.ptr.pointer(to:\.cidr)!.pointee == rhs.ptr.pointer(to:\.cidr)!.pointee
					default:
					return false
				}
			}
			internal func hash(into hasher:inout Hasher) {
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
				return AddressV4(RAW_decode:ptr.pointer(to:\.ip4)!, count:MemoryLayout<in_addr>.size)
			}
			private borrowing func isIPv6() -> Bool {
				return Int32(ptr.pointee.family) == AF_INET6
			}
			private borrowing func addressV6() -> AddressV6? {
				guard Int32(ptr.pointer(to:\.family)!.pointee) == AF_INET6 else {
					return nil
				}
				return AddressV6(RAW_decode:ptr.pointer(to:\.ip6)!, count:MemoryLayout<in6_addr>.size)
			}
		}
		internal init(peer:UnsafeMutablePointer<wg_peer>) {
			#if DEBUG
			guard peer.pointer(to:\.flags)!.pointee.rawValue & WGPEER_REMOVE_ME.rawValue == 0 else {
				fatalError("peer cannot be initialized if it is marked for removal")
			}
			#endif
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
		}
		internal func render(as _:wg_peer.Type, _ handler:(UnsafePointer<wg_peer>) -> Void) {
			var lastAllowedIP:UnsafeMutablePointer<wg_allowedip>? = nil
			for (i, allowedIP) in allowedIPs.enumerated() {
				defer {
					lastAllowedIP = allowedIP.ptr
				}
				if i == 0 {
					ptr.pointer(to:\.first_allowedip)!.pointee = allowedIP.ptr
				} else {
					lastAllowedIP!.pointee.next_allowedip = allowedIP.ptr
				}
			}
			ptr.pointer(to:\.last_allowedip)!.pointee = lastAllowedIP ?? ptr.pointer(to:\.first_allowedip)!.pointee
			handler(ptr)
		}
		deinit {
			free(ptr)
		}
	}
}

public final class Device {
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
	}

	public var privateKey:PrivateKey? {
		get {
			if ptr.pointee.flags.rawValue & WGDEVICE_HAS_PRIVATE_KEY.rawValue != 0 {
				return PrivateKey(RAW_staticbuff:ptr.pointer(to:\.private_key)!)
			} else {
				return nil
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

	private let ptr:UnsafeMutablePointer<wg_device>

	private var pending_remove:[PublicKey:Peer] = [:]
	private var removeMe_peers:[PublicKey:Peer] = [:]
	private var installed_peers = [PublicKey:Peer]()
	public var peerCount:Int {
		return installed_peers.count
	}
	public subscript(peerKey:PublicKey) -> Peer? {
		get {
			return installed_peers[peerKey]
		}
		set {
			if let newPeer = newValue {
				installed_peers[peerKey] = newPeer
				pending_remove.removeValue(forKey:peerKey)
			} else {
				installed_peers.removeValue(forKey:peerKey)
				removeMe_peers[peerKey] = installed_peers[peerKey]!
			}
		}
	}

	fileprivate init(ptr dev_ptr_in:UnsafeMutablePointer<wg_device>) {
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
		ptr = dev_ptr_in
	}

	public static func load(name:String) throws -> Device {
		return try Wireguard.loadExistingDevice(name:name)
	}
}


public enum Endpoint {
	case v4(AddressV4, UInt16)
	case v6(AddressV6, UInt16)
	public init?(_ ptr:UnsafeMutablePointer<wg_endpoint>) {
		switch Int32(ptr.pointer(to:\.addr)!.pointer(to:\.sa_family)!.pointee) {
		case AF_INET:
			let address = AddressV4(RAW_staticbuff:ptr.pointer(to:\.addr4)!.pointer(to:\.sin_addr)!)
			self = .v4(address, ptr.pointer(to: \.addr4)!.pointer(to:\.sin_port)!.pointee)
		case AF_INET6:
			let address = AddressV6(RAW_staticbuff:ptr.pointer(to:\.addr6)!)
			self = .v6(address, ptr.pointer(to:\.addr6)!.pointer(to:\.sin6_port)!.pointee)
		default:
			return nil
		}
	}
}

public enum Error:Swift.Error {
	case interfaceNotFound
	case insufficientPermissions
	case internalError
}
public struct Wireguard {
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
		let wireguardInterface:Device
		do {
			wireguardInterface = try Device.load(name:interfaceName)
		} catch Error.interfaceNotFound {
			try Wireguard.createDevice(name:interfaceName)
			wireguardInterface = try Device.load(name:interfaceName)
		}
		let intPK = wireguardInterface.publicKey
		print(" == Interface Information ==")
		print("Interface Name: \(wireguardInterface.name)")
		print("Interface Public Key: \(intPK!)")
		print("Interface Index: \(wireguardInterface.interfaceIndex)")
		let getInterface = try wireman_rtnetlink.getAddressesV4()
		var interfaceAddressV4 = Set<NetworkV4>()
		var remove4 = Set<AddRemove<NetworkV4>>()
		for address in getInterface {
			if address.interfaceIndex == wireguardInterface.interfaceIndex && address.address != nil {
				let asAddr = AddressV4(address.address!)
				guard asAddr != nil else {
					continue
				}
				let asNetwork = NetworkV4(address:asAddr!, prefix:address.prefix_length)
				interfaceAddressV4.update(with:asNetwork)
				remove4.update(with:.remove(Int32(address.interfaceIndex), asNetwork))
				print("found matching address: \(asNetwork)")
			}
		}
		var interfaceAddressV6 = Set<NetworkV6>()
		var remove6 = Set<AddRemove<NetworkV6>>()
		for address in try wireman_rtnetlink.getAddressesV6() {
			if address.interfaceIndex == wireguardInterface.interfaceIndex && address.address != nil{
				let asAddr = AddressV6(address.address!)
				guard asAddr != nil else {
					continue
				}

				let asNetwork = NetworkV6(address:asAddr!, prefix:address.prefix_length)
				interfaceAddressV6.update(with:asNetwork)
				remove6.update(with:.remove(Int32(address.interfaceIndex), asNetwork))
				print("found matching address: \(String(asNetwork.address))")
			}
		}
		if remove4.count > 0 || remove6.count > 0 {
			_ = try modifyInterface(addressV4:remove4, addressV6:remove6)
		}
	}
}

// extension Wireguard.Peer.AllowedIP:Hashable, Equatable {

// 			public static func == (lhs:Wireguard.Peer.AllowedIP, rhs:Wireguard.Peer.AllowedIP) -> Bool {
// 				switch (lhs, rhs) {
// 				case (.v4(let a), .v4(let b)):
// 					return a == b
// 				case (.v6(let a), .v6(let b)):
// 					return a == b
// 				default:
// 					return false
// 				}
// 			}

// 			public func hash(into hasher:inout Hasher) {
// 				switch self {
// 				case .v4(let a):
// 					hasher.combine("v4")
// 					hasher.combine(a)
// 				case .v6(let a):
// 					hasher.combine("v6")
// 					hasher.combine(a)
// 				}
// 			}

// }