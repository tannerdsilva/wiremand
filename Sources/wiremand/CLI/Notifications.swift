import ArgumentParser

extension CLI {
	struct Notifications:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"notify",
			subcommands:[AddAdmin.self, RemoveAdmin.self, ListAdmins.self]
		)

		struct AddAdmin:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"add a user's email to the administrators notification recipients list."
			)
		
			@OptionGroup
			var globals:CLI.GlobalCLIOptions
			
			@Argument
			var name:String
			
			@Argument
			var email:String
		
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				try daemonDB.addNotifyUser(name:name, email:email)
				try await CertbotExecute.updateNotifyUsers(daemon: daemonDB)
			}
		}
	
		struct RemoveAdmin:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"remove a user's email from the administrators notification recipients list."
			)
		
			@OptionGroup
			var globals:CLI.GlobalCLIOptions
		
			@Argument
			var email:String
		
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				try daemonDB.removeNotifyUser(email:email)
				try await CertbotExecute.updateNotifyUsers(daemon: daemonDB)
			}
		}
		
		struct ListAdmins:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"list the users that are recipients to administrative notification emails."
			)
			
			@OptionGroup
			var globals:CLI.GlobalCLIOptions
			
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				let admins = try daemonDB.getNotifyUsers().sorted(by: { $0.name ?? "" < $1.name ?? "" })
				print(Colors.Cyan("There are \(admins.count) admins that are being notified of system-critical events."))
				for curNotify in admins {
					print("-\t\(curNotify.name!) : \(curNotify.emailAddress)")
				}
			}
		}
	}
}