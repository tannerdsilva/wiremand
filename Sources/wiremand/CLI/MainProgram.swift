import ArgumentParser
import bedrock
import wiremand_databases
import Logging

@main
struct CLI:AsyncParsableCommand {
	struct GlobalCLIOptions:ParsableArguments {
#if DEBUG
//		@Option
		var logLevel:Logging.Logger.Level = .debug
#else
//		@Option(help:ArgumentHelp(visibility:.`private`))
		var logLevel:Logging.Logger.Level = .info
#endif
		
		var databasePath:String = "/var/lib/wiremand"
	}
	
	
	public static let configuration = CommandConfiguration(
		commandName: "wiremand",
		abstract: "A command-line tool for managing WireGuard configurations.",
		subcommands: [
			Installer.self,
			TestMigration.self,
			Server.self,
			Domain.self,
			Client.self,
			Run.self,
		]
	)

	public struct TestMigration:ParsableCommand {
		public static let configuration = CommandConfiguration(
			commandName: "test-migration",
			abstract: "Test the migration of legacy databases to the new format."
		)

		@Argument(help:"the directory path to the legacy database")
		var legacyDBPath:Path = Path("/var/lib/wiremand")

		@Argument(help:"the directory path to the new database")
		var newDBPath:Path = Path("/tmp")

		public mutating func run() throws {
			var logger = Logger(label:"TestMigration")
			logger.logLevel = .info
			let newDB = try WireguardDatabase(base:newDBPath, logLevel:.info)
			try newDB.migrate(oldWireguardBase:legacyDBPath, logger:logger)
			print("Migration test completed successfully.")
		}
	}
}

extension Path:@retroactive ExpressibleByArgument {
	public init?(argument:String) {
		self.init(argument)
	}
}
