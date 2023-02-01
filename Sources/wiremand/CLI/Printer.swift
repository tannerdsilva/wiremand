import ArgumentParser
import Logging
import Foundation

extension CLI {
	struct Printer:ParsableCommand {
		enum Error:Swift.Error {
			case printServerInactive
		}
		
		static let configuration = CommandConfiguration(
			abstract:"manage cloud printers.",
			subcommands:[Make.self, Revoke.self, List.self, SetCutMode.self]
		)
		
		struct SetCutMode:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"set the cut instruction that is executed at the end of each print job."
			)

			@Option(
				help:ArgumentHelp(
					"The MAC address of the device."
				)
			)
			var mac:String? = nil

			@Argument(
				help:ArgumentHelp(
					"The cut mode to assign to this device."
				)
			)
			var cutMode:PrintDB.CutMode
			
			@OptionGroup
			var globals:CLI.GlobalCLIOptions

			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				guard daemonDB.printerDatabase != nil else {
					throw Error.printServerInactive
				}
				try daemonDB.printerDatabase!.assignCutMode(mac:mac!, mode:cutMode)
				try daemonDB.reloadRunningDaemon()
			}
		}
		
		struct List:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"list the printers on this system."
			)

			@OptionGroup
			var globals:CLI.GlobalCLIOptions
			
			@Option(help:ArgumentHelp("In recards to the visible output for this command, how much time is allowed to pass for a client to be considered \"disconnected\".", visibility:.`private`))
			var connectedSecondsThreshold:TimeInterval = 120

			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.printerDatabase != nil else {
					throw Error.printServerInactive
				}
				let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase!.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
				for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
					print(Colors.Yellow("- \(curSub.key)"))
					for curMac in curSub.value {
						print(Colors.dim("\t-\(curMac.mac)"))
						let statusInfo = try daemonDB.printerDatabase!.getPrinterStatus(mac:curMac.mac)
						if (abs(statusInfo.lastSeen.timeIntervalSinceNow) > connectedSecondsThreshold) {
							print(Colors.red("\t  -> Last Connected: \(statusInfo.lastSeen.relativeTimeString())"))
						} else {
							print(Colors.green("\t  -> Connected "), terminator:"")
							print(Colors.dim("(within \(connectedSecondsThreshold) seconds)."))
						}
						if (statusInfo.status.contains("200") == true) {
							print(Colors.green("\t  -> Status: \(statusInfo.status)"))
						} else {
							print(Colors.red("\t  -> Status: \(statusInfo.status)"))
						}
						if (statusInfo.jobs.count == 0) {
							print(Colors.green("\t  -> No pending jobs."))
						} else {
							let sortedJobs = statusInfo.jobs.sorted(by: { $0 < $1 })
							let oldestJob = sortedJobs.first!
							if (abs(oldestJob.timeIntervalSinceNow) > 30) {
								// the queue is not moving because the oldest job is older than it should be. print output in red
								print(Colors.red("\t  -> \(statusInfo.jobs.count) pending jobs. (Oldest job received \(oldestJob.relativeTimeString()))"))
							} else {
								// there are pending jobs but they are moving at a reasonable rate. do not create visual noise, since the status is normal.
								print(Colors.green("\t  -> \(statusInfo.jobs.count) pending jobs."))
							}
						}
					}
				}

			}
		}
		
		struct Revoke:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"revoke a given printer from this system."
			)

			@Option(
				name:.shortAndLong,
				help:ArgumentHelp(
					"The MAC address of the device."
				)
			)
			var mac:String? = nil
			
			@OptionGroup
			var globals:CLI.GlobalCLIOptions

			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				guard daemonDB.printerDatabase != nil else {
					throw Error.printServerInactive
				}
				if (mac == nil || mac!.count == 0) {
					print("Please enter a MAC address to revoke:")
					let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase!.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						mac = readLine()
					} while mac == nil || mac!.count == 0
				}
				
				try daemonDB.printerDatabase!.deauthorizeMacAddress(mac:mac!)
				try daemonDB.reloadRunningDaemon()
			}
		}
		
		struct Make:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"authorize a new printer on this system."
			)

			@Option(
				name:.shortAndLong,
				help:ArgumentHelp(
					"The domain name of the associated printer."
				)
			)
			var domain:String? = nil

			@Option(
				name:.shortAndLong,
				help:ArgumentHelp(
					"The MAC address of the device."
				)
			)
			var mac:String? = nil
			
			@OptionGroup
			var globals:CLI.GlobalCLIOptions

			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				guard daemonDB.printerDatabase != nil else {
					throw Error.printServerInactive
				}
				
				// determine the domain to use
				if (domain == nil || domain!.count == 0) {
					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							print(Colors.Red("There are no subnets configured (this should not be the case)"))
						case 1:
							domain = allSubnets.first!.name
						default:
							print("Please select a domain for this action:")
							for curSub in allSubnets {
								print(Colors.dim("  - \(curSub.name)"))
							}
							repeat {
								print("Domain name: ", terminator:"")
								domain = readLine()?.lowercased()
							} while domain == nil || domain!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:domain!) == true else {
					print(Colors.Red("The domain name '\(domain!)' does not exist"))
					throw CLI.Client.Error.notFound
				}
			
				// determine the mac address to use
				if (mac == nil || mac!.count == 0) {
					print("Please enter a MAC address for the new printer:")
					let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase!.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						mac = readLine()
					} while mac == nil || mac!.count == 0
				}
				let printerMetadata = try daemonDB.printerDatabase!.authorizeMacAddress(mac:mac!.lowercased(), subnet:domain!.lowercased())
				print(Colors.Green("[OK] - Printer assigned to \(domain!)"))
				print(Colors.Cyan("CONFIGURE YOUR PRINT SOURCE TO SEND JOBS TO THIS IP & PORT"))
				print(Colors.Cyan("Address : \(try daemonDB.wireguardDatabase.getServerInternalNetwork().address.string)"))
				print(Colors.Cyan("Port: \(printerMetadata.port)"))
				print(" - - - - - - - - - - - - - - - - - - - - - - - - ")
				print(Colors.Magenta("CONFIGURE PRINT HARDWARE WITH THE FOLLOWING CLOUDPRINT SETTINGS:"))
				print(Colors.Magenta("URL: https://\(domain!)/print"))
				print(Colors.Magenta("Username: \(printerMetadata.username)"))
				print(Colors.Magenta("Password: \(printerMetadata.password)"))
			}
		}
	}
}

extension PrintDB.CutMode:ExpressibleByArgument {
	public init?(argument:String) {
		self.init(rawValue:argument)
	}
	
	public static var allValueStrings = ["full", "partial", "none"]
	
	public static var defaultCompletionKind = CompletionKind.list(Self.allValueStrings)
}