import ArgumentParser
import Logging
import SwiftSlash
import SystemPackage
import AddressKit
import Foundation
import bedrock
import SwiftSMTP

extension CLI {
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
		}
		static let configuration = CommandConfiguration(
			commandName:"install",
			abstract:"installs wiremand on this system."
		)
		
		@Option
		var logLevel:Logging.Logger.Level = .info
		
		@Option
		var interfaceName:String = "wg2930"
		
		@Option
		var wireguardPort:UInt16 = 29300
		
		@Option
		var publicHTTPPort:UInt16 = 8080
		
		@Argument(help:ArgumentHelp("The email address of the primary admin for this system. This is used for SMTP."))
		var adminEmail:String
		
		@Argument(help:ArgumentHelp("The full name of the primary admin for this system. This is used for SMTP."))
		var adminName:String
				
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
				print(" -> [PROMPT](required) external endpoint dns name: ", terminator:"")
				endpoint = readLine()
			} while (endpoint == nil || endpoint!.count == 0)

			let (resExtV4, resExtV6) = try await DigExecutor.resolveAddresses(for:endpoint!)
			
			guard resExtV4 != nil else {
				appLogger.error("there is no A record", metadata:["dns_name":"\(endpoint!)"])
				throw Error.ipv4HostnameUnresolved
			}
			
			guard resExtV6 != nil else {
				appLogger.error("there is no AAAA record", metadata:["dns_name":"\(endpoint!)"])
				throw Error.ipv6HostnameUnresolved
			}
			
			// ask for the client ipv6 scope
			var ipv6Scope:NetworkV6? = nil
			repeat {
				print(" -> [PROMPT](required) vpn internal ipv6 block (cidr where address is servers primary internal address): ", terminator:"")
				if let asString = readLine(), let asNetwork = NetworkV6(cidr:asString) {
					ipv6Scope = asNetwork
				}
			} while ipv6Scope == nil
			
			// ask for the client ipv4 scope
			var ipv4Scope:NetworkV4? = nil
			repeat {
				print(" -> [PROMPT](required) vpn internal ipv4 block (cidr where address is servers primary internal address): ", terminator:"")
				if let asString = readLine(), let asNetwork = NetworkV4(cidr:asString) {
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
			let installCommand = try await Command(bash:"apt-get update && apt-get install wireguard resolvconf dnsmasq stubby nginx certbot -y").runSync()
			guard installCommand.succeeded == true else {
				appLogger.critical("unable to install dnsmasq and wireguard")
				throw Error.unableToInstallDependencies
			}

			appLogger.info("disabling systemd service 'dnsmasq'")
			
			let dnsMasqDisable = try await Command(bash:"systemctl disable dnsmasq && systemctl stop dnsmasq").runSync()
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
				buildConfig += "Address = \(ipv6Scope!.cidrString)\n"
				buildConfig += "Address = \(ipv4Scope!.cidrString)\n"
				buildConfig += "PrivateKey = \(newKeys.privateKey)\n"
				try wgConfigFile.writeAll(buildConfig.utf8)
			})
			
			appLogger.info("configuring dnsmasq...")
			
			// set up the dnsmasq daemon
			let dnsMasqConfFile = try FileDescriptor.open("/etc/dnsmasq.conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite, .groupRead, .otherRead])
			try dnsMasqConfFile.closeAfter({
				var buildConfig = "listen-address=\(ipv6Scope!.address)\n"
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
			let whichCertbot = try await Command(bash:"which certbot").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!
			let whichWg = try await Command(bash:"which wg").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!
			let whichWgQuick = try await Command(bash:"which wg-quick").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!
			let whichSystemcCTL = try await Command(bash:"which systemctl").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!

			appLogger.info("enabling wg-quick@\(interfaceName).service...")

			guard try await Command(bash:"systemctl enable wg-quick@\(interfaceName).service").runSync().succeeded == true else {
				appLogger.critical("unable to enable wg-quick@\(interfaceName).service")
				throw Error.unableToEnableWireguardInterface
			}
			
			appLogger.info("enabling dnsmasq.service...")

			guard try await Command(bash:"systemctl enable dnsmasq.service").runSync().succeeded == true else {
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
			
			// make the user
			let makeUser = try await Command(bash:"useradd -md /var/lib/\(installUserName) \(installUserName)").runSync()
			guard makeUser.succeeded == true else {
				appLogger.critical("unable to create `wiremand` user on the system")
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
			appLogger.info("applying effective CAP_KILL capabilities to executable")
			let setCapResult = try await Command(bash:"sudo setcap CAP_KILL+ep '\(exePath.path)'").runSync()
			guard setCapResult.succeeded == true else {
				appLogger.critical("unable to set effective CAP_KILL capabilities to executable", metadata:["path":"\(exePath.path)", "exitCode":"\(setCapResult.exitCode)"])
				throw Error.capApplyError
			}
			let exeData = try Data(contentsOf:exePath)
			let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute])
			try exeFD.writeAll(exeData)
			try exeFD.close()
			
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

			guard try await Command(bash:"systemctl enable wiremand.service").runSync().succeeded == true else {
				appLogger.critical("unable to enable wiremand.service")
				throw Error.unableToEnableService
			}
			
			appLogger.info("configuring nginx...")

			// begin configuring nginx
			var nginxOwn = try await Command(bash:"chown root:\(installUserName) /etc/nginx && chown root:\(installUserName) /etc/nginx/conf.d && chown root:\(installUserName) /etc/nginx/sites-enabled").runSync()
			guard nginxOwn.succeeded == true else {
				appLogger.critical("unable to change ownership of nginx directories to include wiremand in group")
				throw Error.unableToConfigureNginx
			}
			nginxOwn = try await Command(bash:"chmod 775 /etc/nginx && chmod 775 /etc/nginx/conf.d && chmod 775 /etc/nginx/sites-enabled").runSync()
			guard nginxOwn.succeeded == true else {
				appLogger.critical("unable to change mode of nginx directories to include wiremand in group")
				throw Error.unableToConfigureNginx
			}
			
			// write the upstream config
			let nginxUpstreams = try FileDescriptor.open("/etc/nginx/conf.d/upstreams.conf", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWrite, .groupRead, .otherRead])
			try nginxUpstreams.closeAfter({
				let buildUpstream = "upstream wiremandv4 {\n\tserver 127.0.0.1:8080;\n}\nupstream wiremandv6 {\n\tserver [::1]:8080;\n}\n"
				_ = try nginxUpstreams.writeAll(buildUpstream.utf8)
			})
			
			appLogger.info("installing wiremand bash alias in /etc/skel...")
			
			let bashRCHandle = try FileDescriptor.open("/etc/skel/.bashrc", .writeOnly, options:[.append], permissions:[.ownerReadWrite, .groupRead, .otherRead])
			try bashRCHandle.closeAfter {
				let addLine = "alias wiremand='sudo -u wiremand /opt/wiremand'"
				try bashRCHandle.writeAll(addLine.utf8)
			}
			
			appLogger.info("installing databases...")
 
			let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
			let daemonDBEnv = try! DaemonDB.create(directory:homeDir, publicHTTPPort: UInt16(publicHTTPPort), notify:Email.Contact(name:adminName, emailAddress:adminEmail))
			appLogger.trace("daemon db created...")
			
			try WireguardDatabase.createDatabase(environment:daemonDBEnv, wg_primaryInterfaceName:interfaceName, wg_serverPublicDomainName:endpoint!, wg_resolvedServerPublicIPv4:resExtV4!, wg_resolvedServerPublicIPv6:resExtV6!, wg_serverPublicListenPort:UInt16(wireguardPort), serverIPv6Block: ipv6Scope!, serverIPv4Block:ipv4Scope!, publicKey:newKeys.publicKey, defaultSubnetMask:112)
			appLogger.trace("wireguard database created...")
			
			let _ = try IPDatabase(base:homeDir, apiKey:ipStackKey)
			appLogger.trace("ip database created...")
			
			let ownIt = try await Command(bash:"chown -R \(installUserName):\(installUserName) /var/lib/\(installUserName)/").runSync()
			guard ownIt.succeeded == true else {
				appLogger.critical("unable to change ownership of /var/lib/\(installUserName)/ directory")
				throw Error.chownError
			}
			let modIt = try await Command(bash:"chmod 775 /var/lib/wiremand").runSync()
			guard modIt.succeeded == true else {
				appLogger.critical("unable to modify access bits (chmod) /var/lib/wiremand/ directory")
				throw Error.chmodError
			}
			appLogger.info("acquiring SSL certificates", metadata:["endpoint":"\(endpoint!)"])
			
			try await CertbotExecute.acquireSSL(domain:endpoint!.lowercased(), email:adminEmail)
			try NginxExecutor.install(domain:endpoint!.lowercased())
			try await NginxExecutor.reload()
			
			guard try await Command(bash:"systemctl daemon-reload").runSync().succeeded == true else {
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
		}
		
		static let configuration = CommandConfiguration(
			commandName:"update",
			abstract:"update the wiremand binary on this system.",
			discussion:"must be executed as root user."
		)
		
		@Option
		var logLevel:Logging.Logger.Level = .info
		
		@Option(help:ArgumentHelp("Do not restart the wiremand process after updating the binaries on this system"))
		var noStart:Bool = false
		
		mutating func run() async throws {
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = logLevel
			guard getCurrentUser() == "root" else {
				appLogger.critical("update command must be run as 'root' user.")
				throw Error.mustBeRoot
			}
			let exePath = URL(fileURLWithPath:CommandLine.arguments[0])
			appLogger.info("initiating system update of wiremand process.", metadata:["oldPath":"/opt/wiremand", "updateWith":"\(exePath.path)"])
			let setCapResult = try await Command(bash:"sudo setcap CAP_KILL+ep '\(exePath.path)'").runSync()
			guard setCapResult.succeeded == true else {
				appLogger.critical("unable to set effective CAP_KILL capabilities to executable")
				throw Error.capApplyError
			}
			appLogger.info("applied effective CAP_KILL capabilities to executable.")
			appLogger.info("stopping wiremand service")
			let stopResult = try await Command(bash:"systemctl stop wiremand.service").runSync()
			guard stopResult.succeeded == true else {
				appLogger.critical("unable to stop wiremand.service")
				throw Error.unableToStopService
			}
			appLogger.info("installing executable into /opt"
			)
			// install the executable in the system
			let exeData = try Data(contentsOf:exePath)
			let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute])
			try exeFD.writeAll(exeData)
			try exeFD.close()
			appLogger.info("starting wiremand service")
			let startResult = try await Command(bash:"systemctl start wiremand.service").runSync()
			guard startResult.succeeded == true else {
				appLogger.critical("unable to start wiremand.service")
				throw Error.unableToStartService
			}
<<<<<<< Updated upstream
=======
			
			// update the tab-completion scripts for 
			appLogger.info("copying bash completions to /opt...")
			guard try await Command(bash:"/opt/wiremand --generate-completion-script bash > /opt/wiremand.bash").runSync().succeeded == true else {
				appLogger.critical("unable to generate bash completion scripts")
				throw Error.unableToGenerateBashCompletions
			}
>>>>>>> Stashed changes
			appLogger.info("wiremand successfully updated.")
		}
	}
}