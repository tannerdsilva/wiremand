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
		subcommands:[Run.self, CLI.Installer.self, CLI.Updater.self, CLI.Client.self, CLI.Domain.self, CLI.Printer.self, CLI.IPStack.self]
	)
	
	struct GlobalCLIOptions:ParsableArguments {
#if DEBUG
		@Option
		var logLevel:Logging.Logger.Level = .debug
#else
		@Option(help:ArgumentHelp(visibility:.`private`))
		var logLevel:Logging.Logger.Level = .info
#endif
		
		@Argument(help:ArgumentHelp(visibility:.`private`))
		var databasePath:String = "/var/lib/wiremand"
	}
}

extension DaemonDB {
	convenience init(_ options:CLI.GlobalCLIOptions, running:Bool = false) throws {
		try self.init(base:URL(fileURLWithPath:options.databasePath), running:running)
	}
}