import Foundation
import SwiftSlash
import AddressKit

public struct DigExecutor {
	enum Error:Swift.Error {
		case noAddressesFound
	}
	public static func resolveAddresses(for dnsName:String) async throws -> (AddressV4?, AddressV6?) {
		let v4Addr:AddressV4?
		do {
			guard let digItV4 = try await Command(bash:"dig \(dnsName) A +short").runSync().stdout.first, let asString = String(data:digItV4, encoding:.utf8), digItV4.count > 0, let asAddr = AddressV4(asString) else {
				throw Error.noAddressesFound
			}
			v4Addr = asAddr
		} catch {
			v4Addr = nil
		}
		let v6Addr:AddressV6?
		do {
			guard let digItV6 = try await Command(bash:"dig \(dnsName) AAAA +short").runSync().stdout.first, let asString = String(data:digItV6, encoding:.utf8), digItV6.count > 0, let asAddr = AddressV6(asString) else {
				throw Error.noAddressesFound
			}
			v6Addr = asAddr
		} catch {
			v6Addr = nil
		}
		
		guard v4Addr != nil || v6Addr != nil else {
			WiremanD.appLogger.error("failed to resolve", metadata:["name": "\(dnsName)"])
			throw Error.noAddressesFound
		}
		WiremanD.appLogger.info("successfully resolved", metadata:["name": "\(dnsName)", "ipv4": "\(String(describing: v4Addr?.string))", "ipv6": "\(String(describing:v6Addr?.string))"])
		return (v4Addr, v6Addr)
	}
}
