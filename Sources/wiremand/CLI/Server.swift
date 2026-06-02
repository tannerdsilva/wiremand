import ArgumentParser
import Foundation
import SystemPackage
import SwiftSlash
import Logging
import bedrock
import wiremand_databases

extension CLI {
	struct Server:AsyncParsableCommand {
		enum Error:Swift.Error {
			case notFound
		}
		static let configuration = CommandConfiguration(
			abstract:"manage wireguard server.",
			subcommands:[AddNetwork.self]
		)
		
		struct AddNetwork:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"adds a new network to the servers [Interface] Address."
			)
			
			var globals:GlobalCLIOptions = GlobalCLIOptions()
			
			mutating func run() async throws {
				var appLogger = Logger(label:"wiremand")
				appLogger.logLevel = globals.logLevel
				
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				appLogger.info("getting interface name")
				let interfaceName = String(try wgdb.primaryInterfaceName())
				
				var ipv6Scope:NetworkV6? = nil
				repeat {
					print(" -> [PROMPT](required) vpn internal ipv6 block (cidr where address is servers primary internal address): ", terminator:"")
					if let asString = readLine(), let asNetwork = NetworkV6(asString) {
						ipv6Scope = asNetwork
					}
				} while ipv6Scope == nil
				
				var ipv6ScopeString:EncodedString? = nil
				repeat {
					print(" -> [PROMPT](required) vpn internal ipv6 block name: ", terminator:"")
					if let asString = readLine() {
						ipv6ScopeString = EncodedString(asString)
					}
				} while ipv6ScopeString == nil
				
				// Need to now change the wireguard configuraiton file to add the address.
				let configPath = "/etc/wireguard/\(interfaceName).conf"
				let configFileURL = URL(fileURLWithPath: configPath)
				
				let content = try String(contentsOf: configFileURL, encoding: .utf8)
				var lines = content.components(separatedBy: .newlines)
				
				var inInterfaceSection = false
				var firstAddressLineModified = false
				
				for i in 0..<lines.count {
					let trimmed = lines[i].trimmingCharacters(in: .whitespaces)
					
					if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
						inInterfaceSection = (trimmed == "[Interface]")
						continue
					}
					
					if inInterfaceSection && !firstAddressLineModified && trimmed.lowercased().hasPrefix("address") {
						let parts = trimmed.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
						guard parts.count == 2 else { continue }
						let key = String(parts[0]).trimmingCharacters(in: .whitespaces)
						let valuesStr = String(parts[1]).trimmingCharacters(in: .whitespaces)
						let existing = valuesStr.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
						var updated = existing
						if !updated.contains(ipv6Scope!.cidrstring) {
							updated.append(ipv6Scope!.cidrstring)
						}
						lines[i] = "\(key) = \(updated.joined(separator: ", "))"
						firstAddressLineModified = true
					}
				}
				
				let newContent = lines.joined(separator: "\n")
			//	try newContent.write(to: configFileURL, atomically: true, encoding: .utf8)
				let wgConfigFile = try FileDescriptor.open(configPath, .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite])
				_ = try wgConfigFile.closeAfter({
					try wgConfigFile.writeAll(newContent.utf8)
				})
				
				// Add network to WGDB
				try wgdb.addNetwork(name: ipv6ScopeString!, network: ipv6Scope!)
				
				appLogger.info("Adding IPv6 address \(ipv6Scope!.cidrstring) to \(interfaceName)")
				let ipCmd = try await Command(sh: "sudo ip addr add \(ipv6Scope!.cidrstring) dev \(interfaceName)", environment: CurrentEnvironment.environmentVariables()).runSync()
				guard ipCmd.succeeded else {
					throw NSError(domain: "IPAddFailed", code: 1, userInfo: [
						NSLocalizedDescriptionKey: "Failed to add address to interface \(interfaceName)"
					])
				}
			}
		}
	}
}
