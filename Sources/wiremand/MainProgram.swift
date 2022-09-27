import Foundation
import Commander
import AddressKit
import SystemPackage
import SwiftSlash
import QuickLMDB
import Logging
import SignalStack
import SwiftSMTP
import SwiftDate

extension NetworkV6 {
	func maskingAddress() -> NetworkV6 {
		return NetworkV6(address:AddressV6(self.address.integer & self.netmask.integer), netmask:self.netmask)!
	}
}

@main
struct WiremanD {
	static func getCurrentUser() -> String {
		return String(validatingUTF8:getpwuid(geteuid()).pointee.pw_name) ?? ""
	}
	static func getCurrentDatabasePath() -> URL {
		return URL(fileURLWithPath:String(cString:getpwuid(getuid())!.pointee.pw_dir))
	}
	static func hash(domain:String) throws -> String {
		let domainData = domain.lowercased().data(using:.utf8)!
		return try Blake2bHasher.hash(data:domainData, length:64).base64EncodedString()
	}
	static var appLogger = Logger(label:"wiremand")

	static func main() async throws {
		await AsyncGroup {
			#if DEBUG
			$0.command("ipdb-test",
				Argument<Int>("accessKey")
			) { pidArg in
				let asPid = pid_t(exactly:pidArg)!
				print("\(kill(asPid, 0))")
			}
			#endif
			$0.command("install",
			   Option<String>("interfaceName", default:"wg2930"),
			   Option<String>("user", default:"wiremand"),
			   Option<Int>("wg_port", default:29300),
			   Option<Int>("public_httpPort", default:8080),
			   VariadicOption<String>("email", default:[], description: "administrator email that should receive vital notifications about the system", validator:nil)
			) { interfaceName, installUserName, wgPort, httpPort, emailOptions in
				appLogger.logLevel = .trace
				guard getCurrentUser() == "root" else {
					appLogger.critical("You need to be root to install wiremand.")
					exit(5)
				}

				var adminEmail:String? = nil
				repeat {
					print(" -> [PROMPT](required) your email address (to notify of critical events): ", terminator:"")
					adminEmail = readLine()
				} while adminEmail == nil || adminEmail!.count == 0 || adminEmail!.validateEmail() == false
				
				var adminName:String? = nil
				repeat {
					print(" -> [PROMPT](required) your name: ", terminator:"")
					adminName = readLine()
				} while adminName == nil || adminName!.count == 0
				
				// ask for the public endpoint
				var endpoint:String? = nil
				repeat {
					print(" -> [PROMPT](required) external endpoint dns name: ", terminator:"")
					endpoint = readLine()
				} while (endpoint == nil || endpoint!.count == 0)

				let (resExtV4, resExtV6) = try await DigExecutor.resolveAddresses(for:endpoint!)
				
				guard resExtV4 != nil else {
					Self.appLogger.error("there is no A record", metadata:["dns_name":"\(endpoint!)"])
					exit(11)
				}
				
				guard resExtV6 != nil else {
					Self.appLogger.error("there is no AAAA record", metadata:["dns_name":"\(endpoint!)"])
					exit(12)
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
				
				appLogger.info("installing software...")
				
				// install software
				let installCommand = try await Command(bash:"apt-get update && apt-get install wireguard resolvconf dnsmasq stubby nginx certbot -y").runSync()
				guard installCommand.succeeded == true else {
					appLogger.critical("unable to install dnsmasq and wireguard")
					exit(6)
				}

				appLogger.info("disabling systemd service 'dnsmasq'")
				
				let dnsMasqDisable = try await Command(bash:"systemctl disable dnsmasq && systemctl stop dnsmasq").runSync()
				guard dnsMasqDisable.succeeded == true else {
					appLogger.critical("unable to disable dnsmasq service")
					exit(7)
				}

				appLogger.info("generating wireguard keys...")
				
				// set up the wireguard interface
				let newKeys = try await WireguardExecutor.generateClient()
				
				appLogger.info("writing wireguard configuration...")
				
				let wgConfigFile = try FileDescriptor.open("/etc/wireguard/\(interfaceName).conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite])
				try wgConfigFile.closeAfter({
					var buildConfig = "[Interface]\n"
					buildConfig += "ListenPort = \(wgPort)\n"
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
					exit(8)
				}
				
				appLogger.info("enabling dnsmasq.service...")

				guard try await Command(bash:"systemctl enable dnsmasq.service").runSync().succeeded == true else {
					print("unable to enable dnsmasq.service")
					exit(8)
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
					exit(8)
				}
				
				// get the uid and gid of our new user
				guard let getUsername = getpwnam(installUserName) else {
					appLogger.critical("unable to get uid and gid for wiremand")
					exit(9)
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
					exit(15)
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
					exit(8)
				}
				
				appLogger.info("configuring nginx...")

				// begin configuring nginx
				var nginxOwn = try await Command(bash:"chown root:\(installUserName) /etc/nginx && chown root:\(installUserName) /etc/nginx/conf.d && chown root:\(installUserName) /etc/nginx/sites-enabled").runSync()
				guard nginxOwn.succeeded == true else {
					appLogger.critical("unable to change ownership of nginx directories to include wiremand in group")
					exit(10)
				}
				nginxOwn = try await Command(bash:"chmod 775 /etc/nginx && chmod 775 /etc/nginx/conf.d && chmod 775 /etc/nginx/sites-enabled").runSync()
				guard nginxOwn.succeeded == true else {
					appLogger.critical("unable to change mode of nginx directories to include wiremand in group")
					exit(11)
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
				let daemonDBEnv = try! DaemonDB.create(directory:homeDir, publicHTTPPort: UInt16(httpPort), notify:Email.Contact(name:adminName!, emailAddress:adminEmail!))
				appLogger.trace("daemon db created...")
				
				try WireguardDatabase.createDatabase(environment:daemonDBEnv, wg_primaryInterfaceName:interfaceName, wg_serverPublicDomainName:endpoint!, wg_resolvedServerPublicIPv4:resExtV4!, wg_resolvedServerPublicIPv6:resExtV6!, wg_serverPublicListenPort:UInt16(wgPort), serverIPv6Block: ipv6Scope!, serverIPv4Block:ipv4Scope!, publicKey:newKeys.publicKey, defaultSubnetMask:112)
				appLogger.trace("wireguard database created...")
				
				let _ = try IPDatabase(base:homeDir, apiKey:ipStackKey)
				appLogger.trace("ip database created...")
				
				let ownIt = try await Command(bash:"chown -R \(installUserName):\(installUserName) /var/lib/\(installUserName)/").runSync()
				guard ownIt.succeeded == true else {
					fatalError("unable to change ownership of /var/lib/\(installUserName)/ directory")
				}
				
				appLogger.info("acquiring SSL certificates", metadata:["endpoint":"\(endpoint!)"])
				
				try await CertbotExecute.acquireSSL(domain:endpoint!.lowercased(), email:adminEmail!)
				try NginxExecutor.install(domain:endpoint!.lowercased())
				try await NginxExecutor.reload()
				
				guard try await Command(bash:"systemctl daemon-reload").runSync().succeeded == true else {
					appLogger.critical("unable to reload the systemctl daemon")
					exit(10)
				}
				appLogger.info("Installation complete. Please restart this machine.")
			}
			
			$0.command("update") {
				guard getCurrentUser() == "root" else {
					fatalError("this function must be run as the root user")
				}
				let exePath = URL(fileURLWithPath:CommandLine.arguments[0])
				appLogger.info("initiating system update of wiremand process", metadata:["oldPath":"/opt/wiremand", "updateWith":"\(exePath.path)"])
				let setCapResult = try await Command(bash:"sudo setcap CAP_KILL+ep '\(exePath.path)'").runSync()
				guard setCapResult.succeeded == true else {
					appLogger.critical("unable to set effective CAP_KILL capabilities to executable")
					exit(3)
				}
				appLogger.info("applied effective CAP_KILL capabilities to executable")
				appLogger.info("stopping wiremand service")
				let stopResult = try await Command(bash:"systemctl stop wiremand.service").runSync()
				guard stopResult.succeeded == true else {
					appLogger.critical("unable to stop wiremand.service")
					exit(1)
				}
				appLogger.info("installing executable into /opt")
				// install the executable in the system
				let exeData = try Data(contentsOf:exePath)
				let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute])
				try exeFD.writeAll(exeData)
				try exeFD.close()
				appLogger.info("starting wiremand service")
				let startResult = try await Command(bash:"systemctl start wiremand.service").runSync()
				guard startResult.succeeded == true else {
					appLogger.critical("unable to start wiremand.service")
					exit(2)
				}
				appLogger.info("wiremand successfully updated")
			}
			
			$0.command("notify_add",
			   Option<String?>("name", default:nil, description:"The name of the user that is to be notified of system critical events."),
			   Option<String?>("email", default:nil, description:"The email of the user that is to be notified of system critical events.")
			) { userName, userEmail in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				
				// list existing admins
				let admins = try daemonDB.getNotifyUsers().sorted(by: { $0.name ?? "" < $1.name ?? "" })
				print(Colors.Cyan("There are \(admins.count) admins that are being notified of system-critical events."))
				for curNotify in admins {
					print("-\t\(curNotify.name!) : \(curNotify.emailAddress)")
				}
				
				// prompt for the name that will be added
				var adminName:String? = userName
				repeat {
					print("name: ", terminator:"")
					adminName = readLine()
				} while adminName == nil || adminName!.count == 0
				
				// prompt for the email that needs to be added
				var adminEmail:String? = userEmail
				repeat {
					print("email: ", terminator:"")
					adminEmail = readLine()
				} while adminEmail == nil || adminEmail!.count == 0 || adminEmail!.validateEmail() == false
				guard adminEmail != nil && adminEmail?.validateEmail() == true else {
					print("please enter a valid email address")
					exit(1)
				}
				
				try daemonDB.addNotifyUser(name:adminName!, email: adminEmail!)
				try await CertbotExecute.updateNotifyUsers(daemon: daemonDB)
			}

			$0.command("notify_remove",
				Option<String?>("email", default:nil, description:"The email of the user that is to removed from system critical notifications.")
			) { removeEmail in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				
				// list the existing admins
				let admins = try daemonDB.getNotifyUsers().sorted(by: { $0.name ?? "" < $1.name ?? "" })
				print(Colors.Cyan("There are \(admins.count) admins that are being notified of system-critical events."))
				for curNotify in admins {
					print("-\t\(curNotify.name!) : \(curNotify.emailAddress)")
				}
				
				// prompt for the email that needs to be removed
				var adminEmail:String? = removeEmail
				if adminEmail == nil {
					repeat {
						print("email address to remove: ", terminator:"")
						adminEmail = readLine()
					} while adminEmail == nil || adminEmail!.count == 0 || adminEmail!.validateEmail() == false
				}
				guard adminEmail != nil && adminEmail?.validateEmail() == true else {
					print("please enter a valid email address")
					exit(1)
				}
				
				// remove and reload
				try daemonDB.removeNotifyUser(email:adminEmail!)
				try await CertbotExecute.updateNotifyUsers(daemon:daemonDB)
				print(Colors.Green("[OK] - this user will no longer be notified."))
			}
			
			$0.command("notify_list") {
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				let admins = try daemonDB.getNotifyUsers().sorted(by: { $0.name ?? "" < $1.name ?? "" })
				print(Colors.Cyan("There are \(admins.count) admins that are being notified of system-critical events."))
				for curNotify in admins {
					print("-\t\(curNotify.name!) : \(curNotify.emailAddress)")
				}
			}
			
			$0.command("domain_make",
				Argument<String>("domain", description:"the domain to add to the system")
			) { domainName in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				try await CertbotExecute.acquireSSL(domain: domainName.lowercased(), daemon:daemonDB)
				try NginxExecutor.install(domain: domainName.lowercased())
				try await NginxExecutor.reload()
				let (newSubnet, newSK) = try daemonDB.wireguardDatabase.subnetMake(name:domainName.lowercased())
				let domainHash = try WiremanD.hash(domain:domainName)
				print("[OK] - created domain \(domainName)")
				print("\t->sk: \(newSK)")
				print("\t->dk: \(domainHash)")
				print("\t->subnet: \(newSubnet.cidrString)")
			}
			
			$0.command("domain_list") {
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				let wgDB = daemonDB.wireguardDatabase
				let allDomains = try wgDB.allSubnets()
				for curDomain in allDomains {
					print("\(curDomain.name)")
					print(Colors.Yellow("\t- sk: \(curDomain.securityKey)"))
					print(Colors.Cyan("\t- dk: \(try WiremanD.hash(domain:curDomain.name))"))
					print(Colors.dim("\t- subnet: \(curDomain.network.cidrString)"))
				}
			}
			
			$0.command("punt",
			   Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
			  Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
		   ) { subnet, name in
			   guard getCurrentUser() == "wiremand" else {
				   fatalError("this function must be run as the `wiremand` user")
			   }
			   let dbPath = getCurrentDatabasePath()
			   let daemonDB = try DaemonDB(directory:dbPath, running:false)
			   
			   var useSubnet:String? = subnet
			   if (useSubnet == nil || useSubnet!.count == 0) {

				   let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
				   switch allSubnets.count {
					   case 0:
						   fatalError("there are no subnets configured (this should not be the case)")
					   case 1:
						   print("There is only one subnet configured - it has been automatically selected.")
						   useSubnet = allSubnets.first!.name
					   default:
						   print("Please select the subnet of the client you would like to remove:")
						   for curSub in allSubnets {
							   print(Colors.dim("\t-\t\(curSub.name)"))
						   }
						   repeat {
							   print("subnet name: ", terminator:"")
							   useSubnet = readLine()
						   } while useSubnet == nil || useSubnet!.count == 0
				   }
			   }
			   guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
				   fatalError("the subnet name '\(useSubnet!)' does not exist")
			   }
			   
			   var useClient:String? = name
			   if (useClient == nil || useClient!.count == 0) {
				   let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
				   switch allClients.count {
					   case 0:
						   print(Colors.Yellow("There are no clients on this subnet yet."))
						   exit(1)
					   default:
						   print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
						   for curClient in allClients {
							   print(Colors.dim("\t-\t\(curClient.name)"))
						   }
				   }
				   repeat {
					   print("client name (optional): ", terminator:"")
					   useClient = readLine()
				   } while useClient == nil
			   }
				
				
				let newInvalidDate:Date
				if (useClient!.count == 0) {
					appLogger.debug("punting all clients in subnet", metadata:["subnet": "\(useSubnet!)"]);
					do {
						newInvalidDate = try daemonDB.wireguardDatabase.puntAllClients(subnet:useSubnet!)
					} catch LMDBError.notFound {
						appLogger.error("no clients exist under this subnet. nothing to punt.")
						exit(1)
					}
				} else {
					appLogger.debug("punting individual client", metadata:["subnet": "\(useSubnet!)", "client": "\(useClient!)"])
					newInvalidDate = try daemonDB.wireguardDatabase.puntClientInvalidation(subnet:useSubnet!, name:useClient!)
				}
				appLogger.info("successfully punted", metadata:["now invalidating on": "\(newInvalidDate)"])
			}
			
			$0.command("domain_revoke",
				Argument<String>("domain", description:"the domain to remove from the system")
			) { domainStr in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				try! daemonDB.wireguardDatabase.subnetRemove(name:domainStr.lowercased())
				try! DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
				try! await DNSmasqExecutor.reload()
				try! NginxExecutor.uninstall(domain:domainStr.lowercased())
				try! await NginxExecutor.reload()
				try! await CertbotExecute.removeSSL(domain:domainStr)
			}
			
			$0.command("printer_make",
			   Option<String?>("mac", default:nil, description:"the mac address of the printer to authorized"),
			   Option<String?>("subnet", default:nil, description:"the subnet name that the printer will be assigned to")
			) { mac, subnet in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				// ask for the subnet if needed
				var useSubnet:String? = subnet
				if (useSubnet == nil || useSubnet!.count == 0) {
					print("Please chose a subnet for this printer:")
					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					for curSub in allSubnets {
						print(Colors.dim("\t-\t\(curSub.name)"))
					}
					repeat {
						print("subnet name: ", terminator:"")
						useSubnet = readLine()
					} while useSubnet == nil || useSubnet!.count == 0
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}
				
				var useMac:String? = mac
				if (useMac == nil || useMac!.count == 0) {
					print("Please enter a MAC address for the new printer:")
					let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				let printerMetadata = try daemonDB.printerDatabase.authorizeMacAddress(mac:useMac!.lowercased(), subnet:useSubnet!)
				print(Colors.Green("[OK] - Printer assigned to \(useSubnet!)"))
				print(Colors.Yellow("\tPrinter username: - \(printerMetadata.username)"))
				print(Colors.Yellow("\tPrinter password: - \(printerMetadata.password)"))
				print(" - - - - - - - - - - - - - - - - - ")
				print(Colors.Cyan("\tServer print port: \(printerMetadata.port)"))
				print(Colors.Cyan("\tServer print address: \(try daemonDB.wireguardDatabase.getServerInternalNetwork().address.string)"))
				try daemonDB.reloadRunningDaemon()
			}
			
			$0.command("printer_revoke",
			   Option<String?>("mac", default:nil, description:"the mac address of the printer to authorized")
			) { mac in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				var useMac:String? = mac
				if (useMac == nil || useMac!.count == 0) {
					print("Please enter a MAC address to revoke:")
					let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				
				try daemonDB.printerDatabase.deauthorizeMacAddress(mac:useMac!)
				try daemonDB.reloadRunningDaemon()
			}
			
			$0.command("printer_list") {
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
				for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
					print(Colors.Yellow("- \(curSub.key)"))
					for curMac in curSub.value {
						print(Colors.dim("\t-\t\(curMac.mac)"))
						let statusInfo = try daemonDB.printerDatabase.getPrinterStatus(mac:curMac.mac)
						print("\t-> Last Connected: \(statusInfo.lastSeen)")
						print("\t-> Status: \(statusInfo.status)")
						print("\t-> \(statusInfo.jobs.count) Pending Jobs: \(statusInfo.jobs.sorted(by: { $0 < $1 }))")
					}
				}
			}
			
			$0.command("printer_set_cutmode",
			   Option<String?>("mac", default:nil, description:"the mac address of the printer to edit the cut mode"),
				Option<String?>("cut", default:nil, description:"the cut mode to assign to the printer. may be 'full', 'partial', or 'none'")
			) { mac, cut in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				var useMac:String? = mac
				if (useMac == nil || useMac!.count == 0) {
					print("Please enter a MAC address to edit:")
					let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac.mac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				
				var useCut:String? = cut
				if (useCut == nil || useCut!.count == 0) {
					repeat {
						print("Cut mode [ full | partial | none ]: ", terminator:"")
						useCut = readLine()
					} while PrintDB.CutMode(rawValue:useCut!) == nil
				}
				guard let cutMode = PrintDB.CutMode(rawValue:useCut!) else {
					appLogger.critical("Invalid cut mode specified")
					exit(5)
				}
				try daemonDB.printerDatabase.assignCutMode(mac:useMac!, mode:cutMode)
				try daemonDB.reloadRunningDaemon()
			}
			
			$0.command("client_provision_v4",
				Option<String?>("subnet", default:nil, description:"the name of the subnet that the client belongs to"),
				Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
			) { subnet, name in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the `wiremand` user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				var useSubnet:String? = subnet
				if (useSubnet == nil || useSubnet!.count == 0) {

					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							fatalError("there are no subnets configured (this should not be the case)")
						case 1:
							print("There is only one subnet configured - it has been automatically selected.")
							useSubnet = allSubnets.first!.name
						default:
							print("Please select the subnet of the client you would like to remove:")
							for curSub in allSubnets {
								print(Colors.dim("\t-\t\(curSub.name)"))
							}
							repeat {
								print("subnet name: ", terminator:"")
								useSubnet = readLine()
							} while useSubnet == nil || useSubnet!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}
				
				var useClient:String? = name
				if (useClient == nil || useClient!.count == 0) {
					let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
					switch allClients.count {
						case 0:
							print(Colors.Yellow("There are no clients on this subnet yet."))
							exit(1)
						default:
							print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
							for curClient in allClients {
								print(Colors.dim("\t-\t\(curClient.name)"))
							}
					}
					repeat {
						print("client name: ", terminator:"")
						useClient = readLine()
					} while useClient == nil && useClient!.count == 0
				}
				let (_, _, _, _, _, interfaceName) = try daemonDB.wireguardDatabase.getWireguardConfigMetas()
				let (newV4, curV6, pubString) = try daemonDB.wireguardDatabase.clientAssignIPv4(subnet:useSubnet!, name:useClient!)
				try await WireguardExecutor.updateExistingClient(publicKey:pubString, with:curV6, and:newV4, interfaceName:interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName)
				
				print("On the client [Peer], please update allowed-ips to the following value:\n")
				print("AllowedIPs=\(curV6.string)/128,\(newV4.string)/32")
			}
			
			$0.command("client_revoke",
			   Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
			   Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
			) { subnet, name in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the `wiremand` user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				var useSubnet:String? = subnet
				if (useSubnet == nil || useSubnet!.count == 0) {

					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							fatalError("there are no subnets configured (this should not be the case)")
						case 1:
							print("There is only one subnet configured - it has been automatically selected.")
							useSubnet = allSubnets.first!.name
						default:
							print("Please select the subnet of the client you would like to remove:")
							for curSub in allSubnets {
								print(Colors.dim("\t-\t\(curSub.name)"))
							}
							repeat {
								print("subnet name: ", terminator:"")
								useSubnet = readLine()
							} while useSubnet == nil || useSubnet!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}
				
				var useClient:String? = name
				if (useClient == nil || useClient!.count == 0) {
					let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
					switch allClients.count {
						case 0:
							print(Colors.Yellow("There are no clients on this subnet yet."))
							exit(1)
						default:
							print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
							for curClient in allClients {
								print(Colors.dim("\t-\t\(curClient.name)"))
							}
					}
					repeat {
						print("client name: ", terminator:"")
						useClient = readLine()
					} while useClient == nil && useClient!.count == 0
				}
				try daemonDB.wireguardDatabase.clientRemove(subnet:useSubnet!, name:useClient!)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
			}
			
			$0.command("client_make",
				Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
				Option<String?>("name", default:nil, description:"the name of the client that the key will be created for"),
				Option<String?>("publicKey", default:nil, description:"the public key of the client that is being added"),
				Flag("noDNS", default:false, description:"do not include DNS information in the configuration"),
				Flag("ipv4", default:false, description:"assign this client an ipv4 address as well as an ipv6 address")
			) { subnetName, clientName, pk, noDNS, withIPv4 in
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				
				var useSubnet:String? = subnetName
				if (useSubnet == nil || useSubnet!.count == 0) {

					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							fatalError("there are no subnets configured (this should not be the case)")
						case 1:
							print("There is only one subnet configured - it has been automatically selected.")
							useSubnet = allSubnets.first!.name
						default:
							print("Please select the subnet of the client you would like to remove:")
							for curSub in allSubnets {
								print(Colors.dim("\t-\t\(curSub.name)"))
							}
							repeat {
								print("subnet name: ", terminator:"")
								useSubnet = readLine()
							} while useSubnet == nil || useSubnet!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}

				var useClient:String? = clientName
				if (useClient == nil || useClient!.count == 0) {
					let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
					switch allClients.count {
						case 0:
							print(Colors.Yellow("There are no clients on this subnet yet."))
						default:
							print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
							for curClient in allClients {
								print(Colors.dim("\t-\t\(curClient.name)"))
							}
					}
					repeat {
						print("client name: ", terminator:"")
						useClient = readLine()
					} while useClient == nil && useClient!.count == 0
				}
				guard try daemonDB.wireguardDatabase.validateNewClientName(subnet:useSubnet!, clientName:useClient!) == true else {
					fatalError("the client name '\(useClient!)' cannot be used")
				}
				
				// we will make the keys on behalf of the client
				let newKeys = try await WireguardExecutor.generateClient()
				
				var usePublicKey:String? = pk
				let usePSK:String = newKeys.presharedKey
				if (usePublicKey == nil) {
					usePublicKey = newKeys.publicKey
				}
				
				let (newClientAddress, optionalV4) = try daemonDB.wireguardDatabase.clientMake(name:useClient!, publicKey:usePublicKey!, subnet:useSubnet!, ipv4:withIPv4)
				
				let (wg_dns_name, wg_port, wg_internal_network, serverV4, serverPub, interfaceName) = try daemonDB.wireguardDatabase.getWireguardConfigMetas()
				
				var buildKey = "[Interface]\n"
				if pk == nil {
					buildKey += "PrivateKey = " + newKeys.privateKey + "\n"
				}
				buildKey += "Address = " + newClientAddress.string + "/128\n"
				if optionalV4 != nil {
					buildKey += "Address = " + optionalV4!.string + "/32\n"
				}
				if noDNS == false {
					buildKey += "DNS = " + wg_internal_network.address.string + "\n"
				}
				buildKey += "[Peer]\n"
				buildKey += "PublicKey = " + serverPub + "\n"
				buildKey += "PresharedKey = " + newKeys.presharedKey + "\n"
				buildKey += "AllowedIPs = " + wg_internal_network.cidrString
				if (optionalV4 != nil) {
					buildKey += ", \(serverV4)/32\n"
				} else {
					buildKey += "\n"
				}
				buildKey += "Endpoint = " + wg_dns_name + ":\(wg_port)" + "\n"
				buildKey += "PersistentKeepalive = 25" + "\n"
				
				try await WireguardExecutor.install(publicKey: usePublicKey!, presharedKey: usePSK, address: newClientAddress, addressv4:optionalV4, interfaceName: interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
				try daemonDB.wireguardDatabase.serveConfiguration(buildKey, forPublicKey:usePublicKey!)
				let subnetHash = try WiremanD.hash(domain:useSubnet!).addingPercentEncoding(withAllowedCharacters:.alphanumerics)!
				let buildURL = "\nhttps://\(useSubnet!)/wg_getkey?dk=\(subnetHash)&pk=\(usePublicKey!.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)\n"
				print("\(buildURL)")
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
				try await DNSmasqExecutor.reload()
			}
			
			$0.command("client_list") {
				guard getCurrentUser() == "wiremand" else {
					appLogger.critical("this function must be run as the wiremand user")
					exit(11)
				}
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:false)
				let allClients = try daemonDB.wireguardDatabase.allClients()
				let subnetSort = Dictionary(grouping:allClients, by: { $0.subnetName })
				for subnetToList in subnetSort.sorted(by: { $0.key < $1.key }) {
					print(Colors.Yellow("\(subnetToList.key)"))
					let sortedClients = subnetToList.value.sorted(by: { $0.name < $1.name })
					for curClient in sortedClients {
						// print the online status
						if (curClient.lastHandshake == nil) {
							print(Colors.dim("\t-\t\(curClient.name)"))
						} else {
							if curClient.lastHandshake!.timeIntervalSinceNow > -150 {
								print(Colors.Green("\t-\t\(curClient.name)"))
							} else if curClient.invalidationDate.timeIntervalSinceNow < 43200 {
								print(Colors.Red("\t-\t\(curClient.name)"))
							} else {
								print("\t-\t\(curClient.name)")
							}
						}
					}
				}
			}
						
			$0.command("run") {
				enum Error:Swift.Error {
					case handshakeCheckError
					case endpointCheckError
					case databaseActionError
					case noEndpointProvided
				}
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				appLogger.logLevel = .info
				let dbPath = getCurrentDatabasePath()
				let daemonDB = try DaemonDB(directory:dbPath, running:true)
				await SignalStack.global.add(signal: SIGHUP, { _ in
					Task.detached {
						appLogger.info("port sync triggered")
						try await daemonDB.printerDatabase.portSync()
					}
				})
				let interfaceName = try daemonDB.wireguardDatabase.primaryInterfaceName()
				let tcpPortBind = try daemonDB.wireguardDatabase.getServerInternalNetwork().address.string
				
				// schedule the handshake checker
				try daemonDB.launchSchedule(.latestWireguardHandshakesCheck, interval:10, { [wgdb = daemonDB.wireguardDatabase, logger = appLogger] in
					do {
						// run the shell command to check for the handshakes associated with the various public keys
						let checkHandshakes = try await Command(bash:"sudo wg show \(interfaceName) latest-handshakes").runSync()
						guard checkHandshakes.succeeded == true else {
							throw Error.handshakeCheckError
						}

						// interpret the handshake data
						// nonzero handhakes will be stored here
						var handshakes = [String:Date]()
						// zero handshakes will be stored here
						var zeros = Set<String>()
						for curLine in checkHandshakes.stdout {
							// split the data by tabs
							let splitLine = curLine.split(separator:9)
							// validate the data between the split
							guard splitLine.count > 1, let publicKeyString = String(data:splitLine[0], encoding:.utf8), let handshakeTime = String(data:splitLine[1], encoding:.utf8), let asTimeInterval = TimeInterval(handshakeTime) else {
								throw Error.handshakeCheckError
							}

							// assign the public key to either the nonzero or zero handshakes variables
							if asTimeInterval == 0 {
								zeros.update(with:publicKeyString)
							} else {
								handshakes[publicKeyString] = Date(timeIntervalSince1970:asTimeInterval)
							}
						}
						
						// run the shell command to check for the endpoints of each client
						var endpoints = [String:String]()
						let checkEndpoints = try await Command(bash:"sudo wg show \(interfaceName) endpoints").runSync()
						guard checkEndpoints.succeeded == true else {
							Self.appLogger.error("was not able to check wireguard client endpoints")
							throw Error.endpointCheckError
						}
						
						for curEndpointLine in checkEndpoints.stdout {
							do {
								guard let lineString = String(data:curEndpointLine, encoding:.utf8), let tabSepIndex = lineString.firstIndex(of:"\t"), lineString.endIndex > tabSepIndex else {
									Self.appLogger.error("invalid line data - no tab break found")
									throw Error.endpointCheckError
								}
								
								let pubKeySectComplete = String(lineString[lineString.startIndex..<tabSepIndex])
								let addrSectComplete = lineString[lineString.index(after:tabSepIndex)..<lineString.endIndex]
								
								Self.appLogger.trace("parsed endpoint data line", metadata:["pubKey":"\(pubKeySectComplete)", "addr":"\(addrSectComplete)"])
								
								guard let portSepIndex = addrSectComplete.lastIndex(of:":"), portSepIndex < addrSectComplete.endIndex else {
									Self.appLogger.trace("client does not have an endpoint", metadata:["pubKey":"\(pubKeySectComplete)"])
									throw Error.noEndpointProvided
								}
								let addrSect = String(addrSectComplete[addrSectComplete.startIndex..<portSepIndex])
								let portSect = String(addrSectComplete[addrSectComplete.index(after:portSepIndex)..<addrSectComplete.endIndex])
								
								guard addrSect.count > 0 && portSect.count > 0 else {
									Self.appLogger.error("unable to parse data line. zero counts were identified", metadata:["addrSect_count": "\(addrSect.count)", "portSect_count": "\(portSect.count)"])
									throw Error.endpointCheckError
								}
								
								guard let _ = UInt16(portSect) else {
									Self.appLogger.error("unable to parse endpoint port", metadata:["port_string": "'\(portSect)'", "string_count": "\(portSect.count)"])
									throw Error.endpointCheckError
								}
								
								// determine if ipv6
								if (addrSect.first == "[" && addrSect.last == "]" && addrSect.contains(":") == true) {
									// ipv6
									let asStr = String(addrSect[addrSect.index(after:addrSect.startIndex)..<addrSect.index(before:addrSect.endIndex)])
									guard let asV6 = AddressV6(asStr) else {
										Self.appLogger.error("unable to parse IPv6 address from wireguard endpoints output", metadata:["ip": "\(asStr)"])
										throw Error.endpointCheckError
									}
									
									endpoints[pubKeySectComplete] = asV6.string
								} else if addrSect.contains(".") == true {
									// ipv4
									guard let asV4 = AddressV4(addrSect) else {
										Self.appLogger.error("unable to parse IPv4 address from wireguard endpoints output", metadata:["ip": "\(addrSect)"])
										throw Error.endpointCheckError
									}
									
									endpoints[pubKeySectComplete] = asV4.string
								} else {
									throw Error.endpointCheckError
								}
							} catch Error.noEndpointProvided {
							}
						}
						
						// save the handshake data to the database
						let takeActions = try wgdb.processHandshakes(handshakes, endpoints:endpoints, all:Set(handshakes.keys).union(zeros))
						var rmI = 0
						for curAction in takeActions {
							switch curAction {
								case let .removeClient(pubKey):
									try? await WireguardExecutor.uninstall(publicKey:pubKey, interfaceName:interfaceName)
									rmI += 1
								case let .resolveIP(ipAddr):
									switch ipAddr.contains(":") {
										case true:
											guard let asAddr = AddressV6(ipAddr) else {
												Self.appLogger.error("unable to parse ipv6 address from database action", metadata:["ip_str":"\(ipAddr)"])
												throw Error.databaseActionError
											}
											try daemonDB.ipdb.installAddress(ipv6:asAddr)
										case false:
											guard let asAddr = AddressV4(ipAddr) else {
												Self.appLogger.error("unable to parse ipv4 address from database action", metadata:["ip_str":"\(ipAddr)"])
												throw Error.databaseActionError
											}
											try daemonDB.ipdb.installAddress(ipv4:asAddr)
									}
							}
						}
						
						if (rmI > 0) {
							try? await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
						}
					} catch let error {
						logger.error("handshake check error", metadata:["error": "\(error)"])
					}
				})
				
				// schedule the ssl renewal
				try daemonDB.launchSchedule(.certbotRenewalCheck, interval:172800) { [logger = appLogger] in
					do {
						try await CertbotExecute.renewCertificates()
						_ = try await NginxExecutor.reload()
					} catch let error {
						logger.error("ssl certificates could not be renewed", metadata:["error": "\(error)"])
					}
				}
				
				var allPorts = [UInt16:TCPServer]()
				try! await daemonDB.printerDatabase.assignPortHandlers(opener: { newPort, _ in
					let newServer = try TCPServer(host:tcpPortBind, port:newPort, db:daemonDB.printerDatabase)
					allPorts[newPort] = newServer
				}, closer: { oldPort in
					allPorts[oldPort] = nil
				})
				let webserver = try PublicHTTPWebServer(daemonDB:daemonDB, pp:daemonDB.printerDatabase, port:daemonDB.getPublicHTTPPort())
				try webserver.run()
				webserver.wait()
			}
		}.run()
	}
}
