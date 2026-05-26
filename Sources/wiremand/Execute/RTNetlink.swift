import Foundation
import Crtnetlink
import Logging

public enum AddressFamily:UInt8, Codable {
	case v4 = 4
	case v6 = 6
	
	public init(from decoder:Decoder) throws {
		var container = try decoder.singleValueContainer()
		switch try container.decode(UInt8.self) {
			case 4:
			self = .v4
			case 6:
			self = .v6
			default:
			fatalError("bad value passed to decoder protocol - AddressFamily")
		}
	}
	
	public func encode(to encoder:Encoder) throws {
		var container = try encoder.singleValueContainer()
		try container.encode(self)
	}
}

extension UInt32 {
	func interfaceIndexName() -> String {
		var databuf = malloc(Int(IF_NAMESIZE));
		defer {
			free(databuf);
		}
		let copyResult = if_indextoname(self, databuf)!
		return String(cString:copyResult)
	}
}

extension RTNetlink {
	public struct InterfaceRecord:Hashable, Codable {
		public let interfaceIndex:Int32
		public let interfaceName:String
	
		public let address:String?
		public let broadcast:String?
	
		init(_ r:UnsafeMutablePointer<ifinfomsg>, _ tb:UnsafeMutablePointer<UnsafeMutablePointer<rtattr>?>?) {
			// interface index and name
			let intInd =  r.pointee.ifi_index;
			self.interfaceIndex = intInd
			var nameBuf = malloc(Int(IF_NAMESIZE));
			defer {
				free(nameBuf)
			}
			self.interfaceName = String(cString:if_indextoname(UInt32(intInd), nameBuf));

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
		
			RTNetlink.logger.trace("InterfaceRecord instance created.", metadata:["interface_index":"\(intInd)", "interface_name":"\(self.interfaceName)", "address":"\(self.address)", "broadcast":"\(self.broadcast)"])
		}
	}
}

extension RTNetlink {
	public struct AddressRecord:Hashable, Codable {
		public let family:AddressFamily
		public let interfaceIndex:Int32
		public let interfaceName:String
		public let prefix_length:UInt8
		public let scope:UInt8
		public let address:String?
		public let local:String?
		public let broadcast:String?
		public let anycast:String?
		
		init(_ r:UnsafeMutablePointer<ifaddrmsg>, _ tb:UnsafeMutablePointer<UnsafeMutablePointer<rtattr>?>?) {
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
			var newBuff = malloc(Int(IF_NAMESIZE));
			defer {
				free(newBuff)
			}
			self.interfaceName = String(cString:if_indextoname(UInt32(intInd), newBuff))
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
			
			RTNetlink.logger.trace("AddressRecord instance created.", metadata:["family":"\(self.family)", "interface_name":"\(self.interfaceName)", "prefix":"\(self.prefix_length)", "scope":"\(self.scope)", "address":"\(self.address)", "local":"\(self.local)", "broadcast":"\(self.broadcast)", "anycast":"\(self.anycast)"])
		}
	}
}

extension RTNetlink {
	public struct RouteRecord:Hashable, Codable {
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
		
		init(_ r:UnsafeMutablePointer<rtmsg>, _ tb:UnsafeMutablePointer<UnsafeMutablePointer<rtattr>?>?) {
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
			var iifResult = get_attribute_uint32_rt(tb, RTA_IIF, &iIntInd);
			if (iifResult == 0) {
				self.inputInterfaceIndex = iIntInd
				var nameBuf = malloc(Int(IF_NAMESIZE));
				defer {
					free(nameBuf)
				}
				self.inputInterfaceName = String(cString:if_indextoname(iIntInd, nameBuf));
			} else {
				self.inputInterfaceIndex = nil
				self.inputInterfaceName = nil
			}
			
			// output interface
			var oIntInd:UInt32 = 0
			var oifResult = get_attribute_uint32_rt(tb, RTA_OIF, &oIntInd);
			if (oifResult == 0) {
				self.outputInterfaceIndex = oIntInd
				var nameBuf = malloc(Int(IF_NAMESIZE));
				defer {
					free(nameBuf)
				}
				self.outputInterfaceName = String(cString:if_indextoname(oIntInd, nameBuf));
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
			var getPriResult = get_attribute_uint32_rt(tb, RTA_PRIORITY, &priInt);
			if getPriResult == 0 {
				self.priority = priInt
			} else {
				self.priority = nil
			}
			
			// table
			var tabInt:UInt32 = 0
			var getTabResult = get_attribute_uint32_rt(tb, RTA_TABLE, &tabInt);
			guard getTabResult == 0 else {
				RTNetlink.logger.critical("no table number provided for routing record")
				fatalError("no routing table")
			}
			self.table = tabInt
			
			RTNetlink.logger.trace("RouteRecord instance created", metadata:["dst":"\(String(describing:self.destination))", "dst_len":"\(self.destination_length)", "src":"\(String(describing:source))", "src_len":"\(self.source_length)", "iif":"\(String(describing:inputInterfaceName))", "oif":"\(String(describing:outputInterfaceName))", "gate":"\(String(describing:self.gateway))", "pri":"\(self.priority)", "table":"\(tabInt)"])
		}
	}
}

public class RTNetlink {
	internal static let logger = Logger(label:"rtnetlink")
	
	enum Error:Swift.Error {
		case receiveLengthError
		case noData
		case internalError
		case noMemory
		case failedToBindNetlink
		case failedToSend
		case dumpError
	}
	
	public static func getInterfaces() throws -> Set<InterfaceRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}

		guard do_interface_dump_request(nl_sock) >= 0 else {
			Self.logger.error("error performing interface dump request")
			throw Error.dumpError
		}

		var interfaces = Set<InterfaceRecord>()

		get_interface_dump_response(nl_sock) { msghdr_answer in
			read_interface(msghdr_answer) { r, tb in
				interfaces.insert(InterfaceRecord(r!, tb))
			}
		}

		return interfaces
	}
	
	public static func getAddressesV4() throws -> Set<AddressRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_address_dump_request_v4(nl_sock) >= 0 else {
			Self.logger.error("error performing address dump request")
			throw Error.dumpError
		}
		var returnRecords = Set<AddressRecord>()
		let getResponsesResult = get_address_dump_response(nl_sock) { msghdr_answer in
			let asDate = Date()
			read_address(msghdr_answer) { r, tb in
				if (r!.pointee.ifa_family == AF_INET || r!.pointee.ifa_family == AF_INET6) {
					let addr = AddressRecord(r!, tb)
					returnRecords.update(with:addr)
				}
			}
		}
		return returnRecords
	}
	
	public static func getAddressesV6() throws -> Set<AddressRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_address_dump_request_v6(nl_sock) >= 0 else {
			Self.logger.error("error performing address dump request")
			throw Error.dumpError
		}
		var returnRecords = Set<AddressRecord>()
		let getResponsesResult = get_address_dump_response(nl_sock) { msghdr_answer in
			let asDate = Date()
			read_address(msghdr_answer) { r, tb in
				if (r!.pointee.ifa_family == AF_INET || r!.pointee.ifa_family == AF_INET6) {
					let addr = AddressRecord(r!, tb)
					returnRecords.update(with:addr)
				}
			}
		}
		return returnRecords
	}
	
	public static func getRoutesV4() throws -> Set<RouteRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_route_dump_request_v4(nl_sock) >= 0 else {
			Self.logger.error("error performing dump request")
			throw Error.dumpError
		}
		var returnRoutes = Set<RouteRecord>()
		let getResponsesResult = get_route_dump_response(nl_sock) { msghdr_answer in
			let asDate = Date()
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

	
	public static func getRoutesV6() throws -> Set<RouteRecord> {
		let nl_sock = open_netlink()
		defer {
			close(nl_sock)
		}
		guard do_route_dump_request_v6(nl_sock) >= 0 else {
			Self.logger.error("error performing route dump request")
			throw Error.dumpError
		}
		var returnRoutes = Set<RouteRecord>()
		let getResponsesResult = get_route_dump_response(nl_sock) { msghdr_answer in
			let asDate = Date()
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
}