import ArgumentParser
import QuickLMDB

extension CLI {
	struct IPStack:ParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"ipstack",
			shouldDisplay:false,
			subcommands:[SetAPIKey.self, GetAPIKey.self]
		)

		struct GetAPIKey:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"get the currently configured IPStack API key."
			)
		
			@OptionGroup
			var globals:CLI.GlobalCLIOptions
		
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				do {
					let key = try daemonDB.ipdb.getIPStackKey()
					print("\(key)")
				} catch LMDBError.notFound {
					print("IPStack not configured.")
				}
			}
		}
	
		struct SetAPIKey:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"set the IPStack API key that wiremand will use."
			)
		
			@OptionGroup
			var globals:CLI.GlobalCLIOptions
		
			@Argument
			var key:String
		
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				try daemonDB.ipdb.setIPStackKey(key)
			}
		}
	}
}