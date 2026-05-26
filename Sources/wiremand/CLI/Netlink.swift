import ArgumentParser
import Foundation
import SystemPackage
import SwiftSlash
import Logging
import bedrock
import wiremand_databases

// what interface is the internet? where is traffic going out to? the DEFAULT route. It's the implied external route.
// identify any virtual tunnel interfaces. Seperate them from our own wireguard interfaces

extension CLI {
	struct Netlink:AsyncParsableCommand {
		enum Error:Swift.Error {
			case notFound
		}
		static let configuration = CommandConfiguration(
			abstract:"manage netlink.",
			subcommands:[PrintAddress.self, PrintInterface.self]
		)
		
		struct PrintAddress:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"prints netlink info"
			)
			
			var globals:GlobalCLIOptions = GlobalCLIOptions()
			
			mutating func run() async throws {
				do {
					// Fetch IPv4 addresses
					let ipv4Addresses = try RTNetlink.getAddressesV4()
					print("IPv4 Addresses")
					for addr in ipv4Addresses {
						let scopeDesc = switch addr.scope {
							case 0: "UNIVERSE"
							case 1: "LINK"
							case 255: "HOST"
							default: "UNKNOWN(\(addr.scope))"
						}
						print("  \(addr.interfaceName): \(addr.address ?? "nil")/\(addr.prefix_length) [scope: \(scopeDesc)]")
					}

					// Fetch IPv6 addresses
					let ipv6Addresses = try RTNetlink.getAddressesV6()
					print("\nIPv6 Addresses")
					for addr in ipv6Addresses {
						print("  \(addr.interfaceName): \(addr.address ?? "nil")/\(addr.prefix_length)")
					}

					// Fetch IPv4 routing table
					let routes = try RTNetlink.getRoutesV4()
					print("\nIPv4 Routes")
					for route in routes {
						let dst = route.destination ?? "*"
						let gw = route.gateway ?? "*"
						let iif = route.inputInterfaceName ?? "-"
						let oif = route.outputInterfaceName ?? "-"
						print("  \(dst) via \(gw) dev \(oif) (iif: \(iif)) table: \(route.table)")
					}

					// JSON Serialization (demonstrates Codable conformance)
					let encoder = JSONEncoder()
					encoder.outputFormatting = .prettyPrinted
					if let json = try? encoder.encode(ipv4Addresses) {
						print("\n📦 Sample JSON (IPv4 Addresses)")
						print(String(decoding: json, as: UTF8.self))
					}

				} catch {
					print("Failed to query network state: \(error.localizedDescription)")
				}
			}
		}

		struct PrintInterface:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"prints netlink interface info"
			)
			
			var globals:GlobalCLIOptions = GlobalCLIOptions()
			
			mutating func run() async throws {
		
				do {
					let interfaces = try RTNetlink.getInterfaces()
					print("Network Interfaces (\(interfaces.count) found)")

					for iface in interfaces {
						print("""
						• \(iface.interfaceName) (index: \(iface.interfaceIndex))
							MAC: \(iface.address ?? "N/A")
							Broadcast: \(iface.broadcast ?? "N/A")
						""")
					}

					// Access by name or index
					if let lo = interfaces.first(where: { $0.interfaceName == "lo" }) {
						print("\nLoopback MAC: \(lo.address ?? "none")")
					}

				} catch {
					print("Failed to fetch interfaces: \(error)")
				}
			}
		}
	}
}