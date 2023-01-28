import ArgumentParser
import Logging
import bedrock
import Foundation

@main
struct CLI:AsyncParsableCommand {
	enum Error:Swift.Error {
		case insufficientPrivilege
	}
	
	static let configuration = CommandConfiguration(
		commandName:"wiremand",
		abstract:"wireguard management daemon and CLI tool.",
		subcommands:[Run.self, CLI.Installer.self, CLI.Updater.self, Client.self, Domain.self, Printer.self]
	)
	
	struct GlobalCLIOptions:ParsableArguments {
#if DEBUG
		var logLevel:Logging.Logger.Level = .debug
#else
		@Argument(help:ArgumentHelp(visibility:.`private`))
		var logLevel:Logging.Logger.Level = .info
#endif
		
		@Argument(help:ArgumentHelp(visibility:.`private`))
		var databasePath:String = FileManager.default.homeDirectoryForCurrentUser.path
	}
}

extension DaemonDB {
	convenience init(_ options:CLI.GlobalCLIOptions, running:Bool = false) throws {
		try self.init(base:URL(fileURLWithPath:options.databasePath), running:running)
	}
}