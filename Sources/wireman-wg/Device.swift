import CWireguardTools
import wireman_db

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#elseif os(Windows)
import ucrt
#endif

public final class Device:Hashable, Equatable {
	private let ptr:UnsafeMutablePointer<wg_device>
	private var pending_remove:[PublicKey:Peer]
	private var installed_peers:[PublicKey:Peer]
	public var count:Int {
		get {
			return installed_peers.count
		}
	}

	public subscript(peerKey:PublicKey) -> Peer? {
		get {
			return installed_peers[peerKey]
		}
		set {
			if newValue != nil {
				newValue!.removeMe = false
				installed_peers[peerKey] = newValue!
				pending_remove.removeValue(forKey:peerKey)
			} else {
				if let wasPreviouslyInstalled = installed_peers.removeValue(forKey:peerKey) {
					pending_remove[peerKey] = wasPreviouslyInstalled
					wasPreviouslyInstalled.removeMe = true
				}
			}
		}
	}
	
	internal init(ptr dev_ptr_in:UnsafeMutablePointer<wg_device>) {
		// ensure that replace peers is not set, as we will be managing the peers ourselves and not providing access to this flag directly.
		dev_ptr_in.pointer(to:\.flags)!.pointee = wg_device_flags(rawValue:dev_ptr_in.pointer(to:\.flags)!.pointee.rawValue & ~WGDEVICE_REPLACE_PEERS.rawValue)
		
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
		pending_remove = [:]
		ptr = dev_ptr_in
	}

	public func set() throws {
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
		guard setDevResult == 0 else {
			print("Error setting device: \(setDevResult)")
			throw Error.insufficientPermissions
		}
		pending_remove.removeAll()
	}	

	deinit {
		free(ptr)
	}
}

extension Device:Sequence {
	public func hash(into hasher:inout Hasher) {
		hasher.combine(interfaceIndex)
	}

	public static func == (lhs:Device, rhs:Device) -> Bool {
		return lhs.interfaceIndex == rhs.interfaceIndex
	}

    public func makeIterator() -> Iterator {
		return Iterator(self.installed_peers)
    }

	public struct Iterator:IteratorProtocol {
		public mutating func next() -> Device.Peer? {
			return iterator.next()
		}

		public typealias Element = Peer

		private var iterator:[PublicKey:Peer].Values.Iterator
		public init(_ device:borrowing [PublicKey:Peer]) {
			self.iterator = device.values.makeIterator()
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
}