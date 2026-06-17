import ArgumentParser
import QuickLMDB
import wiremand_databases
import bedrock

extension CLI {
	/// Get/Set for the IPStack API key.
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
				let ipdb = try IPDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				do {
					let key = try ipdb.getIPStackKey()
					print("\(String(key))")
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
				let ipdb = try IPDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				try ipdb.setIPStackKey(key)
			}
		}
	}
}
