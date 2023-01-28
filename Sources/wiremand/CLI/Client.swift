import ArgumentParser
import SwiftBlake2

extension CLI {
	struct Client:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"manage the clients that may connect to wiremand.",
			subcommands:[Punt.self, ProvisionIPv4.self, Revoke.self, Make.self, List.self, Rename.self]
		)
		
		struct Punt:AsyncParsableCommand {
			@OptionGroup
			var globals:GlobalCLIOptions
		}
		
		struct ProvisionIPv4:AsyncParsableCommand {
			@OptionGroup
			var globals:GlobalCLIOptions
		}
		
		struct Revoke:AsyncParsableCommand {
			@OptionGroup
			var globals:GlobalCLIOptions
		}
		
		struct Make:AsyncParsableCommand {
			@OptionGroup
			var globals:GlobalCLIOptions
		}
		
		struct List:AsyncParsableCommand {
			@Option
			var subnet:String? = nil
			
			@Flag(name:.shortAndLong)
			var windowsLegacy = false
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				var allClients = try daemonDB.wireguardDatabase.allClients()
				if (subnetString != nil) {
					allClients = allClients.filter({ $0.subnetName.lowercased() == subnetString!.lowercased() })
				}
				let subnetSort = Dictionary(grouping:allClients, by: { $0.subnetName })
				
				for subnetToList in subnetSort.sorted(by: { $0.key < $1.key }) {
					
				}
			}
		}
		
		struct Rename:ParsableCommand {
			@Argument
			var publicKey:String
			
			@Argument
			var newName:String
			
			@OptionGroup
			var globals:GlobalCLIOptions
						
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				try daemonDB.wireguardDatabase.clientRename(publicKey:pubKey, name:newName)
			}
		}
	}
}