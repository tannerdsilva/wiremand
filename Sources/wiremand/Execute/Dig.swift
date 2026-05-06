import Foundation
import Logging
import wiremand_databases
import SwiftSlash

public struct DigExecutor {
	enum Error:Swift.Error {
		case noAddressesFound
	}
	public static func resolveAddresses(for dnsName:String, logLevel:Logger.Level) async throws -> (AddressV4?, AddressV6?) {
		var log = Logger(label:"dig-executor")
		log.logLevel = logLevel
		let v4Addr:AddressV4?
		do {
			guard let digItV4 = try await Command("dig \(dnsName) A +short").runSync().stdout.first, let asString = String(data:Data(digItV4), encoding:.utf8), digItV4.count > 0, let asAddr = AddressV4(asString) else {
				throw Error.noAddressesFound
			}
			v4Addr = asAddr
		} catch {
			v4Addr = nil
		}
		let v6Addr:AddressV6?
		do {
			guard let digItV6 = try await Command("dig \(dnsName) AAAA +short").runSync().stdout.first, let asString = String(data:Data(digItV6), encoding:.utf8), digItV6.count > 0, let asAddr = AddressV6(asString) else {
				throw Error.noAddressesFound
			}
			v6Addr = asAddr
		} catch {
			v6Addr = nil
		}
		
		guard v4Addr != nil || v6Addr != nil else {
			log.error("failed to resolve", metadata:["name": "\(dnsName)"])
			throw Error.noAddressesFound
		}
		log.info("successfully resolved", metadata:["name": "\(dnsName)", "ipv4": "\(String(describing: v4Addr?.string))", "ipv6": "\(String(describing:v6Addr?.string))"])
		return (v4Addr, v6Addr)
	}
}
