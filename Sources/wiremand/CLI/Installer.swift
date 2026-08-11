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
			case unsupportedDistribution
			case missingPrerequisite(String)
			case packageManagerUnavailable(String)
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
			case noPublicIPv4
			case unableToResolveTool(String)
			case unableToWriteConfig(String)
			case invalidNetwork(String)
			case invalidSudoers
		}
		public static let configuration = CommandConfiguration(
			commandName:"install",
			abstract:"installs wiremand on this system.",
			shouldDisplay:false
		)
		
		var logLevel:Logging.Logger.Level = .info
		
		@Option
		var interfaceName:String = "wg2930"
		
		@Option
		var wireguardPort:UInt16 = 29300
		
		@Option
		var publicHTTPPort:UInt16 = 8080
		
		/// Returns a trimmed list of the tool names wiremand needs present after
		/// package installation (and, where applicable, managed via sudo).
		private var requiredTools: [String] {
			["wg", "wg-quick", "systemctl", "certbot", "openssl", "nft", "ip", "visudo", "setcap", "mkdir"]
		}
		
		/// Generates a random IPv6 subnet within the private `fd00::/8` (ULA)
		/// range, rendered as a `/64` CIDR. Uses RFC 4193 style: the first byte
		/// is `0xfd`, the next 40 bits form a randomly chosen global ID, and the
		/// following 16 bits form a randomly chosen subnet ID. The result is a
		/// canonical compressed string like `fd1a:2b3c:4d5e:6f78::/64`.
		private func randomULAIPv6Subnet() -> String {
			// 8 bytes: 1 (0xfd) + 5 (global ID) + 2 (subnet ID) fills the first
			// 64 bits of the address (the /64 network); the remaining 64 bits of
			// the 128-bit address are implicit zeros (`::`).
			var bytes = [UInt8](repeating: 0, count: 8)
			for i in 1..<8 {
				bytes[i] = UInt8.random(in: 0...255)
			}
			bytes[0] = 0xfd
			
			let hextet0 = String(format: "%02x%02x", bytes[0], bytes[1])
			let hextet1 = String(format: "%02x%02x", bytes[2], bytes[3])
			let hextet2 = String(format: "%02x%02x", bytes[4], bytes[5])
			let hextet3 = String(format: "%02x%02x", bytes[6], bytes[7])
			return "\(hextet0):\(hextet1):\(hextet2):\(hextet3)::/64"
		}
		
		/// A small convenience for capturing a subprocess exit + stdout, replacing
		/// the many ad-hoc `runSync()` calls with a single call site.
		private func run(_ command:String, arguments:[String] = []) async throws -> (succeeded:Bool, stdout:String, exitCode:Int32) {
			let result = try await Command(command, arguments: arguments).runSync()
			let out = result.stdout.compactMap { String(data:Data($0), encoding:.utf8) }.joined(separator:"\n")
			let code:Int32
			switch result.exit {
				case .code(let c): code = c
				default: code = -1
			}
			return (result.succeeded == true, out, code)
		}
		
		/// Same as `run` but shells out through a shell so redirection/`&&` work.
		private func runShell(_ shellCommand:String) async throws -> (succeeded:Bool, stdout:String, exitCode:Int32) {
			let result = try await Command(sh: shellCommand, environment: CurrentEnvironment.environmentVariables()).runSync()
			let out = result.stdout.compactMap { String(data:Data($0), encoding:.utf8) }.joined(separator:"\n")
			let code:Int32
			switch result.exit {
				case .code(let c): code = c
				default: code = -1
			}
			return (result.succeeded == true, out, code)
		}
		
		/// Resolves a tool's absolute path via `which`. Returns nil (no throw) when
		/// the tool is not found so callers can produce a precise error.
		private func which(_ tool:String) async throws -> String? {
			let result = try await run("which", arguments: [tool])
			guard result.succeeded else { return nil }
			let trimmed = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
			return trimmed.isEmpty ? nil : trimmed
		}
		
		/// Detects the Linux distribution from `/etc/os-release` and returns a
		/// package-manager enum used to choose the install command.
		private enum Distribution {
			case debianLike(pkgManager:String)
			case redhatLike(pkgManager:String)
			case archLike(pkgManager:String)
			case suseLike(pkgManager:String)
			case unknown
		}
		
		private func detectDistribution() async throws -> Distribution {
			let result = try await run("cat", arguments: ["/etc/os-release"])
			guard result.succeeded else { return .unknown }
			let content = result.stdout.lowercased()
			if content.contains("debian") || content.contains("ubuntu") { return .debianLike(pkgManager:"apt-get") }
			if content.contains("fedora") || content.contains("rhel") || content.contains("centos") { return .redhatLike(pkgManager:"dnf") }
			if content.contains("arch") || content.contains("manjaro") { return .archLike(pkgManager:"pacman") }
			if content.contains("suse") || content.contains("opensuse") { return .suseLike(pkgManager:"zypper") }
			return .unknown
		}
		
		/// Builds the package-install command for the detected distribution,
		/// always including nftables (the firewall depends on it).
		private func installCommand(for distro:Distribution) -> String {
			let packages: [String]
			switch distro {
				case .debianLike:
					packages = ["wireguard", "resolvconf", "dnsmasq", "stubby", "certbot", "nftables", "libnftables-dev"]
					return "apt-get update && apt-get install -y \(packages.joined(separator:" "))"
				case .redhatLike(let pm):
					packages = ["wireguard-tools", "dnsmasq", "stubby", "certbot", "nftables"]
					return "\(pm) install -y \(packages.joined(separator:" "))"
				case .archLike(let pm):
					packages = ["wireguard-tools", "dnsmasq", "stubby", "certbot", "nftables"]
					return "\(pm) -S --noconfirm \(packages.joined(separator:" "))"
				case .suseLike(let pm):
					packages = ["wireguard-tools", "dnsmasq", "stubby", "certbot", "nftables"]
					return "\(pm) install -y \(packages.joined(separator:" "))"
				case .unknown:
					return "apt-get update && apt-get install -y wireguard resolvconf dnsmasq stubby certbot nftables libnftables-dev"
			}
		}
		
		/// Atomically writes `content` to `path` (temp file + rename) so a crash
		/// mid-write can never leave a partially-written config on disk.
		private func writeConfigAtomically(_ content:String, to path:String, permissions:FilePermissions) throws {
			// Unique temp name: avoid getpid() (not available on all platforms);
			// a UUID suffix is enough to avoid collisions between concurrent installs.
			let tempPath = path + ".tmp-\(UUID().uuidString)"
			let fd = try FileDescriptor.open(tempPath, .writeOnly, options:[.create, .truncate], permissions: permissions)
			defer { try? fd.close() }
			try fd.writeAll(Data(content.utf8))
			try fd.close()
			// rename() is atomic on POSIX: the old file is replaced in one step.
			guard rename(tempPath, path) == 0 else {
				throw Error.unableToWriteConfig(path)
			}
		}
		
		mutating func run() async throws {
			let installUserName = "wiremand"
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = logLevel
			guard getCurrentUser() == "root" else {
				appLogger.critical("You need to be root to install wiremand.")
				throw Error.mustBeRoot
			}
			
			// --- Prerequisite checks before mutating anything ---
			let distro = try await detectDistribution()
			if case .unknown = distro {
				appLogger.warning("could not detect the Linux distribution; defaulting to apt-get")
			} else {
				appLogger.info("detected distribution: \(String(describing:distro))")
			}
			
			// Tools that must already exist before package installation can even
			// begin (they are not provided by the packages we install).
			let preInstallTools = ["systemctl", "openssl", "ip", "visudo", "mkdir", "which"]
			var preInstallPaths:[String:String] = [:]
			for tool in preInstallTools {
				guard let path = try await which(tool) else {
					appLogger.critical("required tool `\(tool)` was not found on this system.")
					throw Error.unableToResolveTool(tool)
				}
				preInstallPaths[tool] = path
			}
			
			// Public IPv4: derive from the default route. No force-unwrap.
			let routesV4 = try RTNetlink.getRoutesV4()
			let filteredRoutesV4 = routesV4.filter { $0.destination_length == 0 }
			guard let defaultRoute = filteredRoutesV4.first else {
				appLogger.error("there is no default IPv4 route")
				throw Error.ipv4DefaultRouteUnknown
			}
			
			let addressV4 = try RTNetlink.getAddressesV4()
			let filteredV4 = addressV4.filter { $0.interfaceName == defaultRoute.outputInterfaceName && $0.scope == 0 }
			guard let defaultV4Address = filteredV4.first?.address else {
				appLogger.error("no public IPv4 address found on the default-route interface")
				throw Error.noPublicIPv4
			}
			let resExtV4 = AddressV4(defaultV4Address)
			
			// Public IPv6: optional, fall back to [::].
			var resExtV6:AddressV6? = nil
			let addressV6 = try RTNetlink.getAddressesV6()
			let filteredV6 = addressV6.filter { $0.interfaceName == defaultRoute.outputInterfaceName && $0.scope == 0 && !$0.flags.isTemporary }
			if let firstV6 = filteredV6.first, let v6Address = firstV6.address, let parsedV6 = AddressV6(v6Address) {
				resExtV6 = parsedV6
			} else {
				appLogger.warning("there is no valid default IPv6 route, will bind to [::] instead")
				resExtV6 = AddressV6("::")
			}
			
			// ask for the client ip scope. if the user provides no input, fall
			// back to a randomly generated private IPv6 subnet within fd00::/8.
			var ipScope:wiremand_databases.Network? = nil
			let defaultIPv6Subnet = randomULAIPv6Subnet()
			repeat {
				print(" -> [PROMPT](required) vpn internal ip block (cidr where address is servers primary internal address) [default: \(defaultIPv6Subnet)]: ", terminator:"")
				if let asString = readLine() {
					let resolvedInput = asString.trimmingCharacters(in: .whitespacesAndNewlines)
					if resolvedInput.isEmpty {
						// no input: use the suggested default
						if let asNetwork = wiremand_databases.Network(defaultIPv6Subnet) {
							ipScope = asNetwork
						}
					} else if let asNetwork = wiremand_databases.Network(resolvedInput) {
						ipScope = asNetwork
					}
				}
			} while ipScope == nil
			
			var ipScopeString:EncodedString? = nil
			repeat {
				print(" -> [PROMPT](required) vpn internal ip block name: ", terminator:"")
				if let asString = readLine() {
					ipScopeString = EncodedString(asString)
				}
			} while ipScopeString == nil
			
			var ipStackKey:String? = nil
			print(" -> [PROMPT](optional) ipstack api key (press RETURN if you do not wish to use ipstack): ", terminator:"")
			if let asString = readLine(), asString.count > 4 {
				ipStackKey = asString
			}
			
			appLogger.info("clearing umask...")
			umask(000)
			
			appLogger.info("installing software...")
			
			// install software (distribution-aware)
			let installCommand = try await runShell(installCommand(for: distro))
			guard installCommand.succeeded else {
				appLogger.critical("unable to install required software packages")
				throw Error.unableToInstallDependencies
			}
			
			// Resolve the full tool set AFTER package installation: some (nft,
			// certbot, setcap) are provided by the packages we just installed.
			// This validates that every required tool is present.
			for tool in requiredTools {
				guard try await which(tool) != nil else {
					appLogger.critical("required tool `\(tool)` was not found after package installation.")
					throw Error.unableToResolveTool(tool)
				}
			}
			
			appLogger.info("disabling systemd service 'dnsmasq'")
			
			let dnsMasqDisable = try await runShell("systemctl disable dnsmasq && systemctl stop dnsmasq")
			guard dnsMasqDisable.succeeded else {
				appLogger.critical("unable to disable dnsmasq service")
				throw Error.unableToStopDnsmasq
			}
			
			appLogger.info("generating wireguard keys...")
			
			// set up the wireguard interface
			let newKeys = try await WireguardExecutor.generateClient()
			
			appLogger.info("writing wireguard configuration...")
			
			// write the wg config atomically
			var buildConfig = "[Interface]\n"
			buildConfig += "ListenPort = \(wireguardPort)\n"
			buildConfig += "Address = \(ipScope!.cidrstring)\n"
			buildConfig += "PrivateKey = \(newKeys.privateKey)\n"
			try writeConfigAtomically(buildConfig, to:"/etc/wireguard/\(interfaceName).conf", permissions:[.ownerReadWrite])
			
			appLogger.info("configuring dnsmasq...")
			
			// set up the dnsmasq daemon atomically
			var dnsmasqConfig = "listen-address=\(ipScope!.addressString)\n"
			dnsmasqConfig += "listen-address=::1\nlisten-address=127.0.0.1\n"
			dnsmasqConfig += "server=::1#5353\n"
			dnsmasqConfig += "server=127.0.0.1#5353\n"
			dnsmasqConfig += "user=\(installUserName)\n"
			dnsmasqConfig += "group=\(installUserName)\n"
			dnsmasqConfig += "no-hosts\n"
			dnsmasqConfig += "addn-hosts=/var/lib/\(installUserName)/hosts-auto\n"
			dnsmasqConfig += "addn-hosts=/var/lib/\(installUserName)/hosts-manual\n"
			try writeConfigAtomically(dnsmasqConfig, to:"/etc/dnsmasq.conf", permissions:[.ownerReadWrite, .groupRead, .otherRead])
			
			appLogger.info("determining tool paths...")
			
			// find wireguard and wg-quick (already resolved above)
			appLogger.info("enabling wg-quick@\(interfaceName).service...")
			
			guard try await runShell("systemctl enable wg-quick@\(interfaceName).service").succeeded else {
				appLogger.critical("unable to enable wg-quick@\(interfaceName).service")
				throw Error.unableToEnableWireguardInterface
			}
			
			appLogger.info("enabling dnsmasq.service...")
			
			guard try await runShell("systemctl enable dnsmasq.service").succeeded else {
				print("unable to enable dnsmasq.service")
				throw Error.unableToEnableDnsmasq
			}
			
			appLogger.info("reconfiguring systemd-resolved...")
			let fp:FilePermissions = [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute]
			mkdir("/etc/systemd/resolved.conf.d", fp.rawValue)
			let resolvedConfig = "[Resolve]\nDNSStubListener=no\n"
			try writeConfigAtomically(resolvedConfig, to:"/etc/systemd/resolved.conf.d/disableStub.conf", permissions:[.ownerReadWrite, .groupRead, .otherRead])
			
			appLogger.info("making user `wiremand`...")
			
			// make the user if doesn't exist
			let idUser = try await runShell("id \(installUserName)")
			switch idUser.exitCode {
				case 1:
					let makeUser = try await runShell("useradd -md /var/lib/\(installUserName) \(installUserName)")
					guard makeUser.succeeded else {
						appLogger.critical("unable to create `wiremand` user on the system")
						throw Error.unableToAddUser
					}
				case 0:
					appLogger.info("user `\(installUserName)` already exists; reusing it")
				default:
					appLogger.critical("could not determine whether user `\(installUserName)` exists (id exit code \(idUser.exitCode))")
					throw Error.unableToAddUser
			}
			
			// get the uid and gid of our new user
			guard let getUsername = getpwnam(installUserName) else {
				appLogger.critical("unable to get uid and gid for wiremand")
				throw Error.unableToGetUsername
			}
			appLogger.info("wiremand user & group present", metadata:["uid": "\(getUsername.pointee.pw_uid)", "gid":"\(getUsername.pointee.pw_gid)"])
			
			// enable ipv6 forwarding on this system
			let sysctlConfig = "net.ipv6.conf.all.forwarding=1\nnet.ipv4.ip_forward = 1\n"
			try writeConfigAtomically(sysctlConfig, to:"/etc/sysctl.d/10-ip-forward.conf", permissions:[.ownerReadWrite, .groupRead, .otherRead])
			
			appLogger.info("installing sudoers modifications for `\(installUserName)` user...")
			
			// CLI access is gated by membership in the `wiremand` group: only a
			// group member may invoke the CLI as the wiremand user. This is the
			// single privileged entry point. The daemon itself does not use sudo
			// (it runs as wiremand with ambient CAP_NET_ADMIN from the unit); it
			// needs no per-command allowlist. Written via temp+rename, then
			// validated with visudo before it can take effect.
			let sudoAddition = "%wiremand ALL=(wiremand:wiremand) NOPASSWD: /opt/wiremand\n"
			try writeConfigAtomically(sudoAddition, to:"/etc/sudoers.d/\(installUserName)", permissions: [.ownerRead, .groupRead])
			
			// Validate the sudoers fragment before trusting it; a malformed sudoers
			// file can lock root out of sudo entirely.
			let visudoCheck = try await runShell("visudo -cf /etc/sudoers.d/\(installUserName)")
			guard visudoCheck.succeeded else {
				appLogger.critical("sudoers fragment failed validation; NOT leaving it in place")
				try? FileManager.default.removeItem(atPath:"/etc/sudoers.d/\(installUserName)")
				throw Error.invalidSudoers
			}
			appLogger.info("sudoers fragment validated")
			
			appLogger.info("installing executable into /opt...")
			
			// install the executable in the system
			let exePath = URL(fileURLWithPath:CommandLine.arguments[0])
			let exeData = try Data(contentsOf:exePath)
			let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute])
			try exeFD.writeAll(exeData)
			try exeFD.close()
			// The binary is owned by root:wiremand and executable only by owner +
			// the wiremand group, so CLI access requires group membership. It
			// carries a CAP_NET_ADMIN file capability: executing it grants netadmin
			// (the CLI's wg/ip/wg-quick calls run as the invoking wiremand-group
			// member without sudo). Under the systemd unit this file capability is
			// inert because NoNewPrivileges=yes drops file caps; the daemon relies
			// on the unit's ambient CAP_NET_ADMIN instead.
			appLogger.info("restricting executable to the `wiremand` group and granting CAP_NET_ADMIN.")
			guard try await runShell("chown root:wiremand /opt/wiremand && chmod 0750 /opt/wiremand && setcap cap_net_admin=ep '/opt/wiremand'").succeeded else {
				appLogger.critical("unable to set ownership/capabilities on /opt/wiremand")
				throw Error.capApplyError
			}
			
			appLogger.info("copying bash completions to /opt...")
			guard try await runShell("/opt/wiremand --generate-completion-script bash > /opt/wiremand.bash").succeeded else {
				appLogger.critical("unable to generate bash completion scripts")
				throw Error.unableToGenerateBashCompletions
			}
			
			appLogger.info("installing systemd service for wiremand...")
			
			// install the systemd service for the daemon (atomically)
			// The daemon runs as the dedicated non-root `wiremand` user and is
			// granted only the ambient capabilities it needs to manage the
			// WireGuard interface, routes, and nftables (all netlink-based, so
			// CAP_NET_ADMIN suffices). No sudo is required: every privileged
			// helper (`wg`, `ip`, `wg-quick`, in-process nft) works off the
			// ambient capability. NoNewPrivileges hardens against setuid/setcap
			// escalation, which is compatible with ambient (not file) caps.
			var systemdConfig = "[Unit]\n"
			systemdConfig += "Description=wireguard management daemon\n"
			systemdConfig += "After=network-online.target wg-quick@\(interfaceName).service\n"
			systemdConfig += "Wants=network-online.target\n"
			systemdConfig += "Requires=wg-quick@\(interfaceName).service\n"
			systemdConfig += "[Service]\n"
			systemdConfig += "User=\(installUserName)\n"
			systemdConfig += "Group=\(installUserName)\n"
			systemdConfig += "Type=exec\n"
			systemdConfig += "AmbientCapabilities=CAP_NET_ADMIN\n"
			systemdConfig += "CapabilityBoundingSet=CAP_NET_ADMIN\n"
			systemdConfig += "NoNewPrivileges=yes\n"
			systemdConfig += "PrivateTmp=yes\n"
			systemdConfig += "ExecStart=/opt/wiremand run\n"
			systemdConfig += "Restart=always\n\n"
			systemdConfig += "[Install]\n"
			systemdConfig += "WantedBy=multi-user.target\n"
			try writeConfigAtomically(systemdConfig, to:"/etc/systemd/system/wiremand.service", permissions:[.ownerRead, .ownerWrite, .groupRead, .otherRead])
			
			appLogger.info("enabling wiremand.service...")
			
			guard try await runShell("systemctl enable wiremand.service").succeeded else {
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
			
			let makeDirectory = try await runShell("mkdir -p /var/lib/\(installUserName)")
			guard makeDirectory.succeeded else {
				appLogger.critical("unable to create the /var/lib/\(installUserName)/ directory")
				throw Error.unableToGenerateDirectory
			}
			let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
			let _ = try Scheduler(base: homeDir, log: appLogger)
			appLogger.trace("scheduler created...")
			
			FirewallDatabase.deleteDB(base: Path(homeDir.path))
			
			WireguardDatabase.deleteDB(base: Path(homeDir.path))
			let wgdb = try WireguardDatabase(base: Path(homeDir.path), logLevel: logLevel)
			try wgdb.install(wg_primaryInterfaceName: EncodedString(interfaceName), wg_resolvedServerPublicIPv4: resExtV4!, wg_resolvedServerPublicIPv6: resExtV6!, wg_serverPublicListenPort: EncodedUInt16(RAW_native: wireguardPort), serverIPBlock: ipScope!, serverBlockName: ipScopeString!, publicKey: newKeys.publicKey, defaultDomainMask: RAW_byte(RAW_native: 64))
			appLogger.trace("wireguard database created...")
			
			IPDatabase.deleteDB(base: Path(homeDir.path))
			let _ = try IPDatabase(base: Path(homeDir.path), logLevel: logLevel, apiKey: ipStackKey)
			appLogger.trace("ip database created...")
			
			let ownIt = try await runShell("chown -R \(installUserName):\(installUserName) /var/lib/\(installUserName)/ && chown \(installUserName):\(installUserName) /etc/wireguard/\(interfaceName).conf && chmod 775 /etc/wireguard")
			guard ownIt.succeeded else {
				appLogger.critical("unable to change ownership of /var/lib/\(installUserName)/ directory")
				throw Error.chownError
			}
			let modIt = try await runShell("chmod 775 /var/lib/wiremand")
			guard modIt.succeeded else {
				appLogger.critical("unable to modify access bits (chmod) /var/lib/wiremand/ directory")
				throw Error.chmodError
			}
			
			appLogger.info("acquiring self-signed SSL certificates", metadata:["endpoint":"\(String(ipScopeString!))"])
			
			let makeSSLDirectory = try await runShell("mkdir -p /etc/wiremand/ssl")
			guard makeSSLDirectory.succeeded else {
				appLogger.critical("unable to create the /etc/wiremand/ssl directory")
				throw Error.unableToGenerateDirectory
			}
			
			try await SelfSignedCertExecutor.generateCert(interfaceName: interfaceName, logLevel: logLevel)
			
			guard try await runShell("systemctl daemon-reload").succeeded else {
				appLogger.critical("unable to reload the systemctl daemon")
				throw Error.daemonReloadError
			}
			
			appLogger.info("Configuring dnsmasq host files")
			
			guard try await runShell("touch /var/lib/\(installUserName)/hosts-auto && touch /var/lib/\(installUserName)/hosts-manual").succeeded else {
				appLogger.critical("unable to create the hosts-auto and hosts-manual files")
				throw Error.daemonReloadError
			}
			
			guard try await runShell("chmod 644 /var/lib/\(installUserName)/hosts-auto && chmod 644 /var/lib/\(installUserName)/hosts-manual").succeeded else {
				appLogger.critical("unable to change permissions on the hosts-auto and hosts-manual files")
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
			// install the executable in the system (root-run; no sudo needed)
			let exeData = try Data(contentsOf:exePath)
			let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute])
			try exeFD.writeAll(exeData)
			try exeFD.close()
			
			// Re-apply the group-gated CLI posture: root:wiremand, 0750, and the
			// CAP_NET_ADMIN file capability. The daemon ignores this file cap
			// (NoNewPrivileges in its unit); the CLI (invoked by a wiremand-group
			// member) uses it to run wg/ip/wg-quick without sudo.
			let setCapResult = try await Command("chown root:wiremand /opt/wiremand && chmod 0750 /opt/wiremand && setcap cap_net_admin=ep '/opt/wiremand'").runSync()
			guard setCapResult.succeeded == true else {
				appLogger.critical("unable to set ownership/capabilities on /opt/wiremand")
				throw Error.capApplyError
			}
			appLogger.info("applied wiremand-group ownership and CAP_NET_ADMIN to executable.")
			
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