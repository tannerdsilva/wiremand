
import CWireguardTools
import ArgumentParser
import wireman_db
import bedrock_ip
import wireman_rtnetlink
import SystemPackage
import QuickJSON

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
	public final class Peer:Sequence, Hashable, Equatable {
		public typealias Element = AllowedIPsEntry
		public typealias Iterator = Set<AllowedIPsEntry>.Iterator
		public func makeIterator() -> Set<AllowedIPsEntry>.Iterator {
			return allowedIPs.makeIterator()
		}
		
		private let ptr:UnsafeMutablePointer<wg_peer>
		private var allowedIPs:Set<AllowedIPsEntry>

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

		public var publicKey:PublicKey? {
			guard ptr.pointer(to:\.flags)!.pointee.rawValue & WGPEER_HAS_PUBLIC_KEY.rawValue != 0 else {
				return nil
			}
			return PublicKey(RAW_staticbuff:ptr.pointer(to:\.public_key)!)
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
			allowedIPs.update(with:allowIP)
		}

		public func remove(_ allowIP:AllowedIPsEntry) {
			allowedIPs.remove(allowIP)
		}

		public static func == (lhs:Peer, rhs:Peer) -> Bool {
			return lhs.publicKey == rhs.publicKey
		}

		public func hash(into hasher:inout Hasher) {
			hasher.combine(publicKey)
		}

		deinit {
			free(ptr)
		}
	}
}

extension Device.Peer {
	public final class AllowedIPsEntry:Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	    public var debugDescription:String {
			switch (isIPv4()) {
			case true:
				return "AllowedIPsEntry(\"\(String(addressV4()!))/\(ptr.pointer(to:\.cidr)!.pointee)\")"
			case false:
				return "AllowedIPsEntry(\"\(String(addressV6()!))/\(ptr.pointer(to:\.cidr)!.pointee)\")"
			}
		}

		internal let ptr:UnsafeMutablePointer<wg_allowedip>
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
		public static func < (lhs:AllowedIPsEntry, rhs:AllowedIPsEntry) -> Bool {
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

/// loads an existing wireguard interface by name.
/// - parameter name: the name of the interface to load
/// - throws: `Error.interfaceNotFound` if the interface does not exist
/// - throws: `Error.insufficientPermissions` if the user does not have permission to access the interface
/// - throws: `Error.internalError` if the interface could not be loaded for an unknown reason (this should not happen)
internal func loadExistingDevice(name:String) throws -> Device {
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

public func createDevice(name newName:String) throws {
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

extension NetworkV4:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asNet = NetworkV4(argument) else {
			return nil
		}
		self = asNet
	}
}

extension NetworkV6:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asNet = NetworkV6(argument) else {
			return nil
		}
		self = asNet
	}
}


@main
struct InitializeInterface:AsyncParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wireman-wg",
		abstract:"Manage wireguard interfaces",
		subcommands:[
			ParseNetwork.self,
			ConfigureInterface.self,
			ListPeerInfo.self
		]
	)

	struct ListPeerInfo:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"list",
			abstract:"List information about a wireguard interface"
		)

		@Argument(help:"The name of the wireguard interface to manage")
		var interfaceName:String

		mutating func run() async throws {
			let wireguardInterface = try loadExistingDevice(name:interfaceName)
			print(" == Interface Information ==")
			print("Interface Name: \(wireguardInterface.name)")
			print("Interface Public Key: \(wireguardInterface.publicKey!)")
			print(" = = = = = = = = = = = = = =")
			print(" == Peer Information ==")
			print("peer count: \(wireguardInterface.count)")
			for curPeer in wireguardInterface {
				print("Peer Public Key: \(curPeer.publicKey!)")
				// print("Peer Preshared Key: \(curPeer.presharedKey!)")
				for allowedIP in curPeer {
					print(" - \(allowedIP))")
				}
				wireguardInterface[curPeer.publicKey!] = nil
			}
			let randomAddress = NetworkV6("fd00::/8")!
			for i in 0..<10 {
				let newPK = PublicKey(privateKey:PrivateKey())
				let randomPeer = Device.Peer(publicKey:newPK, presharedKey:nil)
				randomPeer.update(with:Device.Peer.AllowedIPsEntry(NetworkV6(address:try randomAddress.randomAddress(), subnetPrefix:128)))
				wireguardInterface[newPK] = randomPeer
			}
			try! wireguardInterface.set()
		}
	}

	struct ParseNetwork:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"parse",
			abstract:"Parse a network address"
		)
		
		@Argument
		var network:NetworkV6

		mutating func run() async throws {
			print("Extension Result: \(try network.randomAddress())")
			let configFD:FileDescriptor
			do {
				configFD = try FileDescriptor.open("/etc/wireman.conf", .readWrite, options:[], permissions:[.ownerReadWrite])
			} catch Errno.noSuchFileOrDirectory {
				configFD = try FileDescriptor.open("/etc/wireman.conf", .readWrite, options:[.create], permissions:[.ownerReadWrite])
				let newConfiguration = try Configuration.generateNew()
				let encoder = try QuickJSON.encode(newConfiguration)
				try configFD.writeAll(encoder)
				try configFD.seek(offset:0, from:.start)
			}
			defer {
				try! configFD.close()
			}

			var buildBytes = [UInt8]()
			let newBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount:1024*4, alignment:1)
			defer {
				newBuffer.deallocate()
			}
			while try configFD.read(into:newBuffer) > 0 {
				buildBytes.append(contentsOf:newBuffer)
			}
			let decodedConfiguration = try QuickJSON.decode(Configuration.self, from:buildBytes, size:buildBytes.count, flags:[.stopWhenDone])
			print("Decoded Configuration: \(decodedConfiguration)")
			
		}
	}

	struct ConfigureInterface:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"configure",
			abstract:"Configure a wireguard interface"
		)

		@Argument(help:"The name of the wireguard interface to manage")
		var interfaceName:String

		@Flag(name:.long, help:"do not create or set the wireguard interface.")
		var wgReadOnly:Bool = false

		mutating func run() throws {
			let wireguardInterface:Device
			do {
				wireguardInterface = try loadExistingDevice(name:interfaceName)
			} catch Error.interfaceNotFound {
				guard wgReadOnly == false else {
					throw Error.interfaceNotFound
				}
				try createDevice(name:interfaceName)
				wireguardInterface = try loadExistingDevice(name:interfaceName)
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
					let asNetwork = NetworkV4(address:asAddr!, subnetPrefix:address.prefix_length)
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

					let asNetwork = NetworkV6(address:asAddr!, subnetPrefix:address.prefix_length)
					interfaceAddressV6.update(with:asNetwork)
					remove6.update(with:.remove(Int32(address.interfaceIndex), asNetwork))
					print("found matching address: \(String(asNetwork.address))")
				}
			}
			if interfaceAddressV4.count > 0 || interfaceAddressV6.count > 0 {
				_ = try modifyInterface(addressV4:remove4, addressV6:remove6)
			} else {
				print("No existing addresses to remove")
			}
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