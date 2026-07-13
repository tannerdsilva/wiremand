import ArgumentParser
import Logging
import SwiftSlash
import SystemPackage
import Foundation
import RAW
import bedrock
import wiremand_databases

extension CLI {
	/// Performs one-time system provisioning for a new WireGuard server.
	/// - Gets the default routes IPv4 and IPv6 address to use as a `public`, permanent endpoint.
	/// - Requests user input for the wiregaurd servers IPv6 and IPv4 network `internal` endpoint.
	/// - Requires: Root privileges, internet access, and a clean Linux environment.
	/// - Steps: Installs dependencies, configures WireGuard/dnsmasq/resolved, creates `wiremand` user,
	///   initializes LMDB databases, generates self-signed SSL certs, and installs systemd service.
	/// - Side Effects: Modifies `/etc/systemd/`, `/etc/wireguard/`, `/etc/dnsmasq.conf`, and `/etc/sudoers.d/`.
	struct Installer:AsyncParsableCommand {
		enum Error:Swift.Error {
			case mustBeRoot
			case ipv4HostnameUnresolved
			case ipv6HostnameUnresolved
			case unableToInstallDependencies
			case unableToStopDnsmasq
			case unableToEnableWireguardInterface
			case unableToEnableDnsmasq
			case unableToAddUser
			case unableToGetUsername
			case capApplyError
			case unableToEnableService
			case unableToConfigureNginx
			case chownError
			case chmodError
			case daemonReloadError
			case unableToGenerateBashCompletions
			case ipv4DefaultRouteUnknown
			case unableToGenerateDirectory
		}
		public static let configuration = CommandConfiguration(
			commandName:"install",
			abstract:"installs wiremand on this system.",
			shouldDisplay:false
		)
		
//		@Option
		var logLevel:Logging.Logger.Level = .info
		
		@Option
		var interfaceName:String = "wg2930"
		
		@Option
		var wireguardPort:UInt16 = 29300
		
		@Option
		var publicHTTPPort:UInt16 = 8080
				
		mutating func run() async throws {
			let installUserName = "wiremand"
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = logLevel
			guard getCurrentUser() == "root" else {
				appLogger.critical("You need to be root to install wiremand.")
				throw Error.mustBeRoot
			}
			
			// ask for the public endpoint
			var endpoint:String? = nil
			repeat {
				print(" -> [PROMPT](required) server public domain name: ", terminator:"")
				endpoint = readLine()
			} while (endpoint == nil || endpoint!.count == 0)

			let routesV4 = try RTNetlink.getRoutesV4()
    		let filteredRoutesV4 = routesV4.filter { $0.destination_length == 0 }
			guard !filteredRoutesV4.isEmpty else {
				appLogger.error("there is no default IPv4 route")
				throw Error.ipv4DefaultRouteUnknown
			}

			let addressV4 = try RTNetlink.getAddressesV4()
      		let filteredV4 = addressV4.filter { $0.interfaceName == filteredRoutesV4.first!.outputInterfaceName && $0.scope == 0 } 

			guard let defaultV4Address = filteredV4.first!.address else {
				appLogger.error("no defaultV4 source address")
				throw Error.ipv4DefaultRouteUnknown
			}

			let resExtV4 = AddressV4(defaultV4Address)

			let addressV6 = try RTNetlink.getAddressesV6()
      		let filteredV6 = addressV6.filter { $0.interfaceName == filteredRoutesV4.first!.outputInterfaceName && $0.scope == 0 && !$0.flags.isTemporary }

			let resExtV6:AddressV6?

			if filteredV6.isEmpty {
				appLogger.warning("there is no valid default IPv6 route, will bind to [::] instead")
				resExtV6 = AddressV6("::")
			} else {
				resExtV6 = AddressV6(filteredV6.first!.address!)
			}
			
			// ask for the client ipv6 scope
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
			
			// ask for the client ipv4 scope
			var ipv4Scope:NetworkV4? = nil
			repeat {
				print(" -> [PROMPT](required) vpn internal ipv4 block (cidr where address is servers primary internal address): ", terminator:"")
				if let asString = readLine(), let asNetwork = NetworkV4(asString) {
					ipv4Scope = asNetwork
				}
			} while ipv4Scope == nil
			
			var ipStackKey:String? = nil
			print(" -> [PROMPT](optional) ipstack api key (press RETURN if you do not wish to use ipstack): ", terminator:"")
			if let asString = readLine(), asString.count > 4 {
				ipStackKey = asString
			}
			
			appLogger.info("clearing umask...")
			umask(000)
			
			appLogger.info("installing software...")
			
			// install software
			let installCommand = try await Command(sh: "apt-get update && apt-get install wireguard resolvconf dnsmasq stubby certbot -y", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard installCommand.succeeded == true else {
				appLogger.critical("unable to install dnsmasq and wireguard")
				throw Error.unableToInstallDependencies
			}

			appLogger.info("disabling systemd service 'dnsmasq'")
			
			let dnsMasqDisable = try await Command(sh: "systemctl disable dnsmasq && systemctl stop dnsmasq", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard dnsMasqDisable.succeeded == true else {
				appLogger.critical("unable to disable dnsmasq service")
				throw Error.unableToStopDnsmasq
			}

			appLogger.info("generating wireguard keys...")
			
			// set up the wireguard interface
			let newKeys = try await WireguardExecutor.generateClient()
			
			appLogger.info("writing wireguard configuration...")
			
			let wgConfigFile = try FileDescriptor.open("/etc/wireguard/\(interfaceName).conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite])
			try wgConfigFile.closeAfter({
				var buildConfig = "[Interface]\n"
				buildConfig += "ListenPort = \(wireguardPort)\n"
				buildConfig += "Address = \(ipv6Scope!.cidrstring)\n"
				buildConfig += "Address = \(ipv4Scope!.cidrstring)\n"
				buildConfig += "PrivateKey = \(newKeys.privateKey)\n"
				try wgConfigFile.writeAll(buildConfig.utf8)
			})
			
			appLogger.info("configuring dnsmasq...")
			
			// set up the dnsmasq daemon
			let dnsMasqConfFile = try FileDescriptor.open("/etc/dnsmasq.conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite, .groupRead, .otherRead])
			try dnsMasqConfFile.closeAfter({
				var buildConfig = "listen-address=\(ipv6Scope!.addressString)\n"
				buildConfig += "listen-address=::1\nlisten-address=127.0.0.1\n"
				buildConfig += "server=::1#5353\n"
				buildConfig += "server=127.0.0.1#5353\n"
				buildConfig += "user=\(installUserName)\n"
				buildConfig += "group=\(installUserName)\n"
				buildConfig += "no-hosts\n"
				buildConfig += "addn-hosts=/var/lib/\(installUserName)/hosts-auto\n"
				buildConfig += "addn-hosts=/var/lib/\(installUserName)/hosts-manual\n"
				try dnsMasqConfFile.writeAll(buildConfig.utf8)
			})
			
			appLogger.info("determining tool paths...")
			
			// find wireguard and wg-quick
			let whichCertbot = try await Command("which", arguments: ["certbot"]).runSync().stdout.compactMap { String(data:Data($0), encoding:.utf8) }.first!
			let whichWg = try await Command("which", arguments: ["wg"]).runSync().stdout.compactMap { String(data:Data($0), encoding:.utf8) }.first!
			let whichWgQuick = try await Command("which", arguments:["wg-quick"]).runSync().stdout.compactMap { String(data:Data($0), encoding:.utf8) }.first!
			let whichSystemcCTL = try await Command("which", arguments:["systemctl"]).runSync().stdout.compactMap { String(data:Data($0), encoding:.utf8) }.first!

			appLogger.info("enabling wg-quick@\(interfaceName).service...")

			guard try await Command(sh: "systemctl enable wg-quick@\(interfaceName).service", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
				appLogger.critical("unable to enable wg-quick@\(interfaceName).service")
				throw Error.unableToEnableWireguardInterface
			}
			
			appLogger.info("enabling dnsmasq.service...")

			guard try await Command(sh: "systemctl enable dnsmasq.service", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
				print("unable to enable dnsmasq.service")
				throw Error.unableToEnableDnsmasq
			}
							
			appLogger.info("reconfiguring systemd-resolved...")
			let fp:FilePermissions = [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute]
			mkdir("/etc/systemd/resolved.conf.d", fp.rawValue)
			let dnsmasqOverride = try FileDescriptor.open("/etc/systemd/resolved.conf.d/disableStub.conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite, .groupRead, .otherRead])
			try dnsmasqOverride.closeAfter {
				var buildConfig = "[Resolve]\n"
				buildConfig += "DNSStubListener=no\n"
				try dnsmasqOverride.writeAll(buildConfig.utf8)
			}

			appLogger.info("making user `wiremand`...")
			
			// make the user if doesn't exist
			let idUser = try await Command(sh: "id \(installUserName)", environment: CurrentEnvironment.environmentVariables()).runSync()
			switch idUser.exit {
				case .code(let exitCode):
					if exitCode == 1 {
						let makeUser = try await Command(sh: "useradd -md /var/lib/\(installUserName) \(installUserName)", environment: CurrentEnvironment.environmentVariables()).runSync()
						guard makeUser.succeeded == true else {
							appLogger.critical("unable to create `wiremand` user on the system")
							throw Error.unableToAddUser
						}
					}
				default:
					throw Error.unableToAddUser
			}
			
			// get the uid and gid of our new user
			guard let getUsername = getpwnam(installUserName) else {
				appLogger.critical("unable to get uid and gid for wiremand")
				throw Error.unableToGetUsername
			}
			appLogger.info("wiremand user & group created", metadata:["uid": "\(getUsername.pointee.pw_uid)", "gid":"\(getUsername.pointee.pw_gid)"])
			
			// enable ipv6 forwarding on this system
			let sysctlFwdFD = try FileDescriptor.open("/etc/sysctl.d/10-ip-forward.conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite, .groupRead, .otherRead])
			try sysctlFwdFD.closeAfter({
				let makeLine = "net.ipv6.conf.all.forwarding=1\nnet.ipv4.ip_forward = 1\n"
				try sysctlFwdFD.writeAll(makeLine.utf8)
			})
			

			appLogger.info("installing soduers modifications for `\(installUserName)` user...")
			
			// add the sudoers modifications for this user
			let sudoersFD = try FileDescriptor.open("/etc/sudoers.d/\(installUserName)", .writeOnly, options:[.create, .truncate], permissions: [.ownerRead, .groupRead])
			try sudoersFD.closeAfter({
				var sudoAddition = "\(installUserName) ALL = NOPASSWD: \(whichWg)\n"
				sudoAddition += "\(installUserName) ALL = NOPASSWD: \(whichWgQuick)\n"
				sudoAddition += "\(installUserName) ALL = NOPASSWD: \(whichCertbot)\n"
				sudoAddition += "\(installUserName) ALL = NOPASSWD: \(whichSystemcCTL) reload *\n"
				sudoAddition += "%wiremand ALL=(wiremand:wiremand) NOPASSWD: /opt/wiremand\n"
				try sudoersFD.writeAll(sudoAddition.utf8)
			})
			
			appLogger.info("installing executable into /opt...")
			
			// install the executable in the system
			let exePath = URL(fileURLWithPath:CommandLine.arguments[0])
			let exeData = try Data(contentsOf:exePath)
			let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute])
			try exeFD.writeAll(exeData)
			try exeFD.close()
			appLogger.info("applying effective CAP_KILL capabilities to executable.")
			let setCapResult = try await Command(sh: "sudo setcap CAP_KILL+ep '/opt/wiremand'", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard setCapResult.succeeded == true else {
				appLogger.critical("unable to set effective CAP_KILL capabilities to executable")
				throw Error.capApplyError
			}
			
			appLogger.info("copying bash completions to /opt...")
			guard try await Command(sh: "/opt/wiremand --generate-completion-script bash > /opt/wiremand.bash", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
				appLogger.critical("unable to generate bash completion scripts")
				throw Error.unableToGenerateBashCompletions
			}
			
			appLogger.info("installing systemd service for wiremand...")
			
			// install the systemd service for the daemon
			let systemdFD = try FileDescriptor.open("/etc/systemd/system/wiremand.service", .writeOnly, options:[.create, .truncate], permissions:[.ownerRead, .ownerWrite, .groupRead, .otherRead])
			try systemdFD.closeAfter({
				var buildConfig = "[Unit]\n"
				buildConfig += "Description=wireguard management daemon\n"
				buildConfig += "After=network-online.target wg-quick@\(interfaceName).service\n"
				buildConfig += "Wants=network-online.target\n"
				buildConfig += "Requires=wg-quick@\(interfaceName).service\n"
				buildConfig += "[Service]\n"
				buildConfig += "User=\(installUserName)\n"
				buildConfig += "Group=\(installUserName)\n"
				buildConfig += "Type=exec\n"
				buildConfig += "ExecStart=/opt/wiremand run\n"
				buildConfig += "Restart=always\n\n"
				buildConfig += "[Install]\n"
				buildConfig += "WantedBy=multi-user.target\n"
				try systemdFD.writeAll(buildConfig.utf8)
			})
			
			appLogger.info("enabling wiremand.service...")

			guard try await Command(sh: "systemctl enable wiremand.service", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
				appLogger.critical("unable to enable wiremand.service")
				throw Error.unableToEnableService
			}
			
			appLogger.info("updating /etc/skel/.bashrc with wiremand conveniences")
			
			let bashRCHandle = try FileDescriptor.open("/etc/skel/.bashrc", .writeOnly, options:[.append], permissions:[.ownerReadWrite, .groupRead, .otherRead])
			try bashRCHandle.closeAfter {
				var addLine = "alias wiremand='sudo -u wiremand /opt/wiremand'\n"
				addLine += "source /opt/wiremand.bash\n"
				try bashRCHandle.writeAll(addLine.utf8)
			}
			
			appLogger.info("installing databases...")

			let makeDirectory = try await Command(sh: "mkdir -p /var/lib/\(installUserName)", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard makeDirectory.succeeded == true else {
				appLogger.critical("unable to create the /var/lib/\(installUserName)/ directory")
				throw Error.unableToGenerateDirectory
			}
			let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
			let _ = try Scheduler(base: homeDir, log: appLogger)
			appLogger.trace("scheduler created...")

			FirewallDatabase.deleteDB(base: Path(homeDir.path))
			
			WireguardDatabase.deleteDB(base: Path(homeDir.path))
			let wgdb = try WireguardDatabase(base: Path(homeDir.path), logLevel: logLevel)
			try wgdb.install(wg_primaryInterfaceName: EncodedString(interfaceName), wg_serverPublicDomainName: EncodedString(endpoint!), wg_resolvedServerPublicIPv4: resExtV4!, wg_resolvedServerPublicIPv6: resExtV6!, wg_serverPublicListenPort: EncodedUInt16(RAW_native: wireguardPort), serverIPv6Block: ipv6Scope!, serverIPv6BlockName: ipv6ScopeString!, serverIPv4Block: ipv4Scope!, publicKey: newKeys.publicKey, defaultDomainMask: RAW_byte(RAW_native: 112))
			appLogger.trace("wireguard database created...")
			
			IPDatabase.deleteDB(base: Path(homeDir.path))
			let _ = try IPDatabase(base: Path(homeDir.path), logLevel: logLevel, apiKey: ipStackKey)
			appLogger.trace("ip database created...")
			
			let ownIt = try await Command(sh: "chown -R \(installUserName):\(installUserName) /var/lib/\(installUserName)/", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard ownIt.succeeded == true else {
				appLogger.critical("unable to change ownership of /var/lib/\(installUserName)/ directory")
				throw Error.chownError
			}
			let modIt = try await Command(sh: "chmod 775 /var/lib/wiremand", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard modIt.succeeded == true else {
				appLogger.critical("unable to modify access bits (chmod) /var/lib/wiremand/ directory")
				throw Error.chmodError
			}

			appLogger.info("acquiring self-signed SSL certificates", metadata:["endpoint":"\(endpoint!)"])

			let makeSSLDirectory = try await Command(sh: "mkdir -p /etc/wiremand/ssl", environment: CurrentEnvironment.environmentVariables()).runSync()
			guard makeDirectory.succeeded == true else {
				appLogger.critical("unable to create the /etc/wiremand/ssl directory")
				throw Error.unableToGenerateDirectory
			}
			
			try await SelfSignedCertExecutor.generateCert(interfaceName: interfaceName, logLevel: logLevel)
			
			guard try await Command(sh: "systemctl daemon-reload", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
				appLogger.critical("unable to reload the systemctl daemon")
				throw Error.daemonReloadError
			}
			
			appLogger.info("Installation complete. Please restart this machine.")
		}
	}
	
	struct Updater:AsyncParsableCommand {
		enum Error:Swift.Error {
			case mustBeRoot
			case capApplyError
			case unableToStopService
			case unableToStartService
			case unableToGenerateBashCompletions
		}
		
		static let configuration = CommandConfiguration(
			commandName:"update",
			abstract:"update the wiremand binary on this system.",
			discussion:"must be executed as root user.",
			shouldDisplay:false
		)
		
		@Flag(help:"do not start the wiremand process after it has been updated on this system.")
		var noRestart = false
		
//		@Option
		var logLevel:Logging.Logger.Level = .info
		
		mutating func run() async throws {
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = logLevel
			guard getCurrentUser() == "root" else {
				appLogger.critical("update command must be run as 'root' user.")
				throw Error.mustBeRoot
			}
			let exePath = URL(fileURLWithPath:CommandLine.arguments[0])
			appLogger.info("initiating system update of wiremand process.", metadata:["oldPath":"/opt/wiremand", "updateWith":"\(exePath.path)"])
			appLogger.info("stopping wiremand service")
			let stopResult = try await Command("systemctl stop wiremand.service").runSync()
			guard stopResult.succeeded == true else {
				appLogger.critical("unable to stop wiremand.service")
				throw Error.unableToStopService
			}
			appLogger.info("installing executable into /opt")
			// install the executable in the system
			let exeData = try Data(contentsOf:exePath)
			let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute])
			try exeFD.writeAll(exeData)
			try exeFD.close()
			
			let setCapResult = try await Command("sudo setcap CAP_KILL+ep '/opt/wiremand'").runSync()
			guard setCapResult.succeeded == true else {
				appLogger.critical("unable to set effective CAP_KILL capabilities to executable")
				throw Error.capApplyError
			}
			appLogger.info("applying effective CAP_KILL capabilities to executable.")
			
			if (noRestart == false) {
				appLogger.info("starting wiremand service")
				let startResult = try await Command("systemctl start wiremand.service").runSync()
				guard startResult.succeeded == true else {
					appLogger.critical("unable to start wiremand.service")
					throw Error.unableToStartService
				}
			}
			appLogger.info("copying bash completions to /opt...")
			guard try await Command("/opt/wiremand --generate-completion-script bash > /opt/wiremand.bash").runSync().succeeded == true else {
				appLogger.critical("unable to generate bash completion scripts")
				throw Error.unableToGenerateBashCompletions
			}
			appLogger.info("wiremand successfully updated.")
		}
	}
}
