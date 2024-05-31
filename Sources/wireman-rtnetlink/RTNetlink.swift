import Crtnetlink
import bedrock_ip

public enum AddressFamily:UInt8 {
	case v4 = 4
	case v6 = 6
}

extension UInt32 {
	fileprivate func interfaceIndexName() -> String {
		let databuf = malloc(Int(IF_NAMESIZE));
		defer {
			free(databuf);
		}
		let copyResult = if_indextoname(self, databuf)!
		return String(cString:copyResult)
	}
}

	public struct InterfaceRecord:Hashable, Equatable {
		public let interfaceIndex:Int32
		public let interfaceName:String
	
		public let address:String?
		public let broadcast:String?
	
		public init(_ r:UnsafeMutablePointer<ifinfomsg>, _ tb:UnsafeMutablePointer<UnsafeMutablePointer<rtattr>?>?) {
			// interface index and name
			let intInd =  r.pointee.ifi_index;
			self.interfaceIndex = intInd
			self.interfaceName = UInt32(intInd).interfaceIndexName()

			// address
			var addr:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_ifla(r.pointee.ifi_family, tb, Int32(IFLA_ADDRESS), &addr)
			if addr != nil {
				self.address = String(cString:addr!)
				free(addr)
			} else {
				self.address = nil
			}
		
			var bcst:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_ifla(r.pointee.ifi_family, tb, Int32(IFLA_BROADCAST), &bcst)
			if bcst != nil {
				self.broadcast = String(cString:bcst!)
				free(bcst)
			} else {
				self.broadcast = nil
			}
		}
	}

	public struct AddressRecord:Hashable {
		public let family:AddressFamily
		public let interfaceIndex:Int32
		public let interfaceName:String
		public let prefix_length:UInt8
		public let scope:UInt8
		public let address:String?
		public let local:String?
		public let broadcast:String?
		public let anycast:String?
		
		public init(_ r:UnsafeMutablePointer<ifaddrmsg>, _ tb:UnsafeMutablePointer<UnsafeMutablePointer<rtattr>?>?) {
			switch r.pointee.ifa_family {
				case UInt8(AF_INET):
				self.family = .v4
				case UInt8(AF_INET6):
				self.family = .v6
				default:
					fatalError("unknown family wtf \(r.pointee.ifa_family)")
			}
			let intInd = r.pointee.ifa_index
			self.interfaceIndex = Int32(intInd);
			self.interfaceName = UInt32(intInd).interfaceIndexName()
			self.prefix_length = r.pointee.ifa_prefixlen
			self.scope = r.pointee.ifa_scope
			
			// address
			var addr:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_ifa(r.pointee.ifa_family, tb, Int32(IFA_ADDRESS), &addr)
			if addr != nil {
				self.address = String(cString:addr!)
				free(addr)
			} else {
				self.address = nil
			}
			
			// local address
			var loca:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_ifa(r.pointee.ifa_family, tb, Int32(IFA_LOCAL), &loca)
			if loca != nil {
				self.local = String(cString:loca!)
				free(loca)
			} else {
				self.local = nil
			}

			// broadcast
			var bcst:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_ifa(r.pointee.ifa_family, tb, Int32(IFA_BROADCAST), &bcst)
			if bcst != nil {
				self.broadcast = String(cString:bcst!)
				free(bcst)
			} else {
				self.broadcast = nil
			}
			
			// anycast
			var anyc:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_ifa(r.pointee.ifa_family, tb, Int32(IFA_ANYCAST), &anyc)
			if anyc != nil {
				self.anycast = String(cString:anyc!)
				free(anyc)
			} else {
				self.anycast = nil
			}
		}
	}

	public struct RouteRecord:Hashable {
		public let family:AddressFamily
		public let destination:String?
		public let destination_length:UInt8
		public let source:String?
		public let source_length:UInt8
		public let inputInterfaceIndex:UInt32?
		public let inputInterfaceName:String?
		public let outputInterfaceIndex:UInt32?
		public let outputInterfaceName:String?
		public let gateway:String?
		public let priority:UInt32?
		public let table:UInt32
		
		public init(_ r:UnsafeMutablePointer<rtmsg>, _ tb:UnsafeMutablePointer<UnsafeMutablePointer<rtattr>?>?) {
			switch r.pointee.rtm_family {
				case UInt8(AF_INET):
				self.family = .v4
				case UInt8(AF_INET6):
				self.family = .v6
				default:
					fatalError("unknown family wtf")
			}
			// destination address
			var dst:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_rt(r.pointee.rtm_family, tb, RTA_DST, &dst)
			if (dst != nil) {
				self.destination = String(cString:dst!)
				free(dst)
			} else {
				self.destination = nil
			}
			self.destination_length = r.pointee.rtm_dst_len
			
			// source address
			var src:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_rt(r.pointee.rtm_family, tb, RTA_DST, &src)
			if (src != nil) {
				self.source = String(cString:dst!)
				free(src)
			} else {
				self.source = nil
			}
			self.source_length = r.pointee.rtm_src_len
			
			// input interface
			var iIntInd:UInt32 = 0
			let iifResult = get_attribute_uint32_rt(tb, RTA_IIF, &iIntInd);
			if (iifResult == 0) {
				self.inputInterfaceIndex = iIntInd
				self.inputInterfaceName = UInt32(iIntInd).interfaceIndexName()
			} else {
				self.inputInterfaceIndex = nil
				self.inputInterfaceName = nil
			}
			
			// output interface
			var oIntInd:UInt32 = 0
			let oifResult = get_attribute_uint32_rt(tb, RTA_OIF, &oIntInd);
			if (oifResult == 0) {
				self.outputInterfaceIndex = oIntInd
				self.outputInterfaceName = UInt32(oIntInd).interfaceIndexName()
			} else {
				self.outputInterfaceIndex = nil
				self.outputInterfaceName = nil
			}
			
			// gateway
			var gate:UnsafeMutablePointer<CChar>? = nil
			get_attribute_data_rt(r.pointee.rtm_family, tb, RTA_GATEWAY, &gate);
			if gate != nil {
				self.gateway = String(cString:gate!)
				free(gate)
			} else {
				self.gateway = nil
			}
			
			// priority
			var priInt:UInt32 = 0
			let getPriResult = get_attribute_uint32_rt(tb, RTA_PRIORITY, &priInt);
			if getPriResult == 0 {
				self.priority = priInt
			} else {
				self.priority = nil
			}
			
			// table
			var tabInt:UInt32 = 0
			let getTabResult = get_attribute_uint32_rt(tb, RTA_TABLE, &tabInt);
			guard getTabResult == 0 else {
				fatalError("no routing table")
			}
			self.table = tabInt
		}
	}

	public enum Error:Swift.Error {
		case receiveLengthError
		case noData
		case internalError
		case noMemory
		case failedToBindNetlink
		case failedToSend
		case dumpError
	}

	public enum AddRemove<T>:Hashable where T:Hashable {
		case add(Int32, T)
		case remove(Int32, T)

		public func hash(into hasher:inout Hasher) {
			switch self {
				case .add(let intI, let t):
				hasher.combine(intI)
				hasher.combine(t)
				case .remove(let intI, let t):
				hasher.combine(intI)
				hasher.combine(t)
			}
		}

		fileprivate func interfaceIndex() -> Int32 {
			switch self {
				case .add(let intI, _):
				return intI
				case .remove(let intI, _):
				return intI
			}
		}

		fileprivate func underlying() -> T {
			switch self {
				case .add(_, let t):
				return t
				case .remove(_, let t):
				return t
			}
		}

		public static func == (lhs:AddRemove<T>, rhs:AddRemove<T>) -> Bool {
			let lhsAddr = lhs.underlying()
			let rhsAddr = rhs.underlying()
			let lhsInt = lhs.interfaceIndex()
			let rhsInt = rhs.interfaceIndex()
			return lhsAddr == rhsAddr && lhsInt == rhsInt
		}
	}
	public func modifyInterface(addressV4:Set<AddRemove<NetworkV4>>, addressV6:Set<AddRemove<NetworkV6>>) throws {
		guard addressV4.count > 0 || addressV6.count > 0 else {
			return
		}
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:((addressV4.count * Crtnetlink.address_message_size_v4()) + (addressV6.count * Crtnetlink.address_message_size_v6())) * 2)
		defer {
			buffer.deallocate()
		}
		var encLen:size_t = 0
		var sequence:UInt32 = 0
		for curV4 in addressV4 {
			switch curV4 {
				case .add(let inter, let addr):
				encLen += Crtnetlink.add_address_assignment_request_v4(buffer.baseAddress, encLen, buffer.count, inter, addr.address.RAW_access_staticbuff({ $0.assumingMemoryBound(to:UInt32.self).pointee }), addr.subnetPrefix, &sequence)
				case .remove(let inter, let addr):
				encLen += Crtnetlink.add_address_removal_request_v4(buffer.baseAddress, encLen, buffer.count, inter, addr.RAW_access_staticbuff({ $0.assumingMemoryBound(to:UInt32.self).pointee }), addr.subnetPrefix, &sequence)
			}
		}
		for curV6 in addressV6 {
			switch curV6 {
				case .add(let inter, let addr):
				encLen += Crtnetlink.add_address_assignment_request_v6(buffer.baseAddress, encLen, buffer.count, inter, addr.address.RAW_access_staticbuff({ $0.assumingMemoryBound(to:in6_addr.self).pointee }), addr.subnetPrefix, &sequence)
				case .remove(let inter, let addr):
				encLen += Crtnetlink.add_address_removal_request_v6(buffer.baseAddress, encLen, buffer.count, inter, addr.RAW_access_staticbuff({ $0.assumingMemoryBound(to:in6_addr.self).pointee }), addr.subnetPrefix, &sequence)
			}
		}
		
		do_address_mod_message(nl_sock, buffer.baseAddress!, encLen)

		var success = 0
		var fail = 0
		if get_address_mod_responses(nl_sock, { msghdr_answer in
			if read_address_mod(msghdr_answer, { r, tb in
				success += 1
			}) != 0 {
				fail += 1
			}
		}) != 0 {
			throw Error.internalError
		}
	}
	
	public func getInterfaces() throws -> [String:InterfaceRecord] {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_interface_dump_request(nl_sock) >= 0 else {
			throw Error.dumpError
		}
		var buildInts = [String:InterfaceRecord]()
		let getResponsesResult = get_interface_dump_response(nl_sock) { msghdr_answer in
			read_interface(msghdr_answer) { r, tb in
				let int = InterfaceRecord(r!, tb)
				buildInts[int.interfaceName] = int
			}
		}
		guard getResponsesResult >= 0 else {
			throw Error.internalError
		}
		return buildInts
	}
	
	public func getAddressesV4() throws -> Set<AddressRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_address_dump_request_v4(nl_sock) >= 0 else {
			throw Error.dumpError
		}
		var returnRecords = Set<AddressRecord>()
		let getResponsesResult = get_address_dump_response(nl_sock, { msghdr_answer in
			read_address(msghdr_answer) { r, tb in
				if (r!.pointee.ifa_family == AF_INET || r!.pointee.ifa_family == AF_INET6) {
					let addr = AddressRecord(r!, tb)
					returnRecords.update(with:addr)
				}
			}
		})
		return returnRecords
	}
	
	public func getAddressesV6() throws -> Set<AddressRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_address_dump_request_v6(nl_sock) >= 0 else {
			throw Error.dumpError
		}
		var returnRecords = Set<AddressRecord>()
		let getResponsesResult = get_address_dump_response(nl_sock, { msghdr_answer in
			read_address(msghdr_answer, { r, tb in
				if (r!.pointee.ifa_family == AF_INET || r!.pointee.ifa_family == AF_INET6) {
					let addr = AddressRecord(r!, tb)
					returnRecords.update(with:addr)
				}
			})
		})
		return returnRecords
	}
	
	public func getRoutesV4() throws -> Set<RouteRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_route_dump_request_v4(nl_sock) >= 0 else {
			throw Error.dumpError
		}
		var returnRoutes = Set<RouteRecord>()
		let getResponsesResult = get_route_dump_response(nl_sock) { msghdr_answer in
			var isDefault = false
			var buffPtr:UnsafeMutablePointer<CChar>? = nil
			var buildThing:Int32 = 0
			var asString:String? = nil
			read_route(msghdr_answer) { r, tb in
				if (r!.pointee.rtm_family == AF_INET || r!.pointee.rtm_family == AF_INET6) {
					let rr = RouteRecord(r!, tb)
					returnRoutes.update(with:rr)
				}
			}
		}
		return returnRoutes
	}

	
	public func getRoutesV6() throws -> Set<RouteRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_route_dump_request_v6(nl_sock) >= 0 else {
			throw Error.dumpError
		}
		var returnRoutes = Set<RouteRecord>()
		let getResponsesResult = get_route_dump_response(nl_sock) { msghdr_answer in
			var isDefault = false
			
			read_route(msghdr_answer) { r, tb in
				if (r!.pointee.rtm_family == AF_INET || r!.pointee.rtm_family == AF_INET6) {
					let rr = RouteRecord(r!, tb)
					returnRoutes.update(with:rr)
				}
			}
		}
		return returnRoutes
	}