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
		@Argument
		var logLevel:Logging.Logger.Level = .debug
#else
		@Argument
		var logLevel:Logging.Logger.Level = .info
#endif
		
		@Argument
		var databasePath:String = "/var/lib/wiremand"
	}
}

extension DaemonDB {
	convenience init(_ options:CLI.GlobalCLIOptions, running:Bool = false) throws {
		try self.init(base:URL(fileURLWithPath:options.databasePath), running:running)
	}
}