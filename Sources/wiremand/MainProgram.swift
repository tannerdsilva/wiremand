import Foundation
import Commander
import AddressKit
import SystemPackage
import SwiftSlash
import QuickLMDB

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

    static func main() async throws {
        await AsyncGroup {
            $0.command("install",
               Option<String>("interfaceName", default:"wg2930"),
               Option<String>("user", default:"wiremand"),
               Option<Int>("wg_port", default:29300),
               Option<Int>("public_httpPort", default:8080),
               Option<Int>("private_tcpPrintPort_start", default:9100),
               Option<Int>("private_tcpPrintPort_end", default:9300)
            ) { interfaceName, installUserName, wgPort, httpPort, tcpPrintPortBegin, tcpPrintPortEnd in
                guard getCurrentUser() == "root" else {
                    print("You need to be root to install wiremand.")
                    exit(5)
                }
                
                // ask for the public endpoint
                var endpoint:String? = nil
                repeat {
                    print("public endpoint dns name: ", terminator:"")
                    endpoint = readLine()
                } while (endpoint == nil || endpoint!.count == 0)

                // ask for the client ipv6 scope
                var ipv6Scope:NetworkV6? = nil
                repeat {
                    print("vpn ipv6 block (cidr where address is servers primary internal address): ", terminator:"")
                    if let asString = readLine(), let asNetwork = NetworkV6(cidr:asString) {
                        ipv6Scope = asNetwork
                    }
                } while ipv6Scope == nil
				
				// ask for the client ipv6 scope
				var ipv4Scope:NetworkV4? = nil
				repeat {
					print("vpn ipv4 block (cidr where address is servers primary internal address): ", terminator:"")
					if let asString = readLine(), let asNetwork = NetworkV4(cidr:asString) {
						ipv4Scope = asNetwork
					}
				} while ipv4Scope == nil

                print("installing software...")
                
                // install software
                let installCommand = try await Command(bash:"apt-get update && apt-get install wireguard dnsmasq stubby nginx certbot -y").runSync()
                guard installCommand.succeeded == true else {
                    print("unable to install dnsmasq and wireguard")
                    exit(6)
                }
                
                print("generating wireguard keys...")
                
                // set up the wireguard interface
                let newKeys = try await WireguardExecutor.generate()
                
                print("writing wireguard configuration...")
                
                let wgConfigFile = try FileDescriptor.open("/etc/wireguard/\(interfaceName).conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite])
                try wgConfigFile.closeAfter({
                    var buildConfig = "[Interface]\n"
                    buildConfig += "ListenPort = \(wgPort)\n"
                    buildConfig += "Address = \(ipv6Scope!.cidrString)\n"
					buildConfig += "Address = \(ipv4Scope!.cidrString)\n"
                    buildConfig += "PrivateKey = \(newKeys.privateKey)\n"
                    try wgConfigFile.writeAll(buildConfig.utf8)
                })
                
                print("enabling wireguard services...")
                
                let enableWireguard = try await Command(bash:"systemctl enable wg-quick@\(interfaceName) && systemctl start wg-quick@\(interfaceName)").runSync()
                guard enableWireguard.succeeded == true else {
                    print("unable to enable wireguard service")
                    exit(7)
                }
                
                print("configuring dnsmasq...")
                
                // set up the dnsmasq daemon
                let dnsMasqConfFile = try FileDescriptor.open("/etc/dnsmasq.conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite, .groupRead, .otherRead])
                try dnsMasqConfFile.closeAfter({
                    var buildConfig = "listen-address=\(ipv6Scope!.address)\n"
                    buildConfig += "interface=\(interfaceName)\n"
                    buildConfig += "except-interface=lo\n"
                    buildConfig += "bind-interfaces\n"
                    buildConfig += "server=::1\n"
                    buildConfig += "server=127.0.0.1\n"
                    buildConfig += "user=\(installUserName)\n"
                    buildConfig += "group=\(installUserName)\n"
                    buildConfig += "no-hosts\n"
                    buildConfig += "addn-hosts=/var/lib/\(installUserName)/hosts-auto\n"
                    buildConfig += "addn-hosts=/var/lib/\(installUserName)/hosts-manual\n"
                    try dnsMasqConfFile.writeAll(buildConfig.utf8)
                })
                
                print("making user `wiremand`...")
                
                // make the user
                let makeUser = try await Command(bash:"useradd -md /var/lib/\(installUserName) -U -G www-data \(installUserName)").runSync()
                guard makeUser.succeeded == true else {
                    print("unable to create `wiremand` user on the system")
                    exit(8)
                }
                
                // get the uid and gid of our new user
                guard let getUsername = getpwnam(installUserName) else {
                    print("unable to get uid and gid for wiremand")
                    exit(9)
                }
                print("\t->\tcreated new uid \(getUsername.pointee.pw_uid) and gid \(getUsername.pointee.pw_gid)")
                
                // enable ipv6 forwarding on this system
                let sysctlFwdFD = try FileDescriptor.open("/etc/sysctl.d/10-ip-forward.conf", .writeOnly, options:[.create, .truncate], permissions:[.ownerReadWrite, .groupRead, .otherRead])
                try sysctlFwdFD.closeAfter({
                    let makeLine = "net.ipv6.conf.all.forwarding=1\nnet.ipv4.ip_forward = 1\n"
                    try sysctlFwdFD.writeAll(makeLine.utf8)
                })
                
                print("determining tool paths...")
                
                // find wireguard and wg-quick
                let whichCertbot = try await Command(bash:"which certbot").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!
                let whichWg = try await Command(bash:"which wg").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!
                let whichWgQuick = try await Command(bash:"which wg-quick").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!
                let whichSystemcCTL = try await Command(bash:"which systemctl").runSync().stdout.compactMap { String(data:$0, encoding:.utf8) }.first!

                print("installing soduers modifications for `\(installUserName)` user...")
                
                // add the sudoers modifications for this user
                let sudoersFD = try FileDescriptor.open("/etc/sudoers.d/\(installUserName)", .writeOnly, options:[.create, .truncate], permissions: [.ownerRead, .groupRead])
                try sudoersFD.closeAfter({
                    var sudoAddition = "\(installUserName) ALL = NOPASSWD: \(whichWg)\n"
                    sudoAddition += "\(installUserName) ALL = NOPASSWD: \(whichWgQuick)\n"
                    sudoAddition += "\(installUserName) ALL = NOPASSWD: \(whichCertbot)\n"
                    sudoAddition += "\(installUserName) ALL = NOPASSWD: \(whichSystemcCTL) reload *\n"
                    try sudoersFD.writeAll(sudoAddition.utf8)
                })
                
                print("installing executable into /opt...")
                
                // install the executable in the system
                let exePath = URL(fileURLWithPath:CommandLine.arguments[0])
                let exeData = try Data(contentsOf:exePath)
                let exeFD = try FileDescriptor.open("/opt/wiremand", .writeOnly, options:[.create], permissions: [.ownerReadWriteExecute, .groupRead, .groupExecute, .otherRead, .otherExecute])
                try exeFD.writeAll(exeData)
                try exeFD.close()
                
                print("installing systemd service for wiremand...")
                
                // install the systemd service for the daemon
                let systemdFD = try FileDescriptor.open("/etc/systemd/system/wiremand.service", .writeOnly, options:[.create, .truncate], permissions:[.ownerRead, .ownerWrite, .groupRead, .otherRead])
                try systemdFD.closeAfter({
                    var buildConfig = "[Unit]\n"
                    buildConfig += "Description=wireguard management daemon\n"
                    buildConfig += "After=network-online.target\n"
                    buildConfig += "Wants=network-online.target\n\n"
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
                
                let enableWiremand = try await Command(bash:"systemctl enable wiremand").runSync()
                guard enableWiremand.succeeded == true else {
                    print("unable to enable wiremand service")
                    exit(15)
                }
                
                // begin configuring nginx
                var nginxOwn = try await Command(bash:"chown root:\(installUserName) /etc/nginx && chown root:\(installUserName) /etc/nginx/conf.d && chown root:\(installUserName) /etc/nginx/sites-enabled").runSync()
                guard nginxOwn.succeeded == true else {
                    print("unable to change ownership of nginx directories to include wiremand in group")
                    exit(10)
                }
                nginxOwn = try await Command(bash:"chmod 775 /etc/nginx && chmod 775 /etc/nginx/conf.d && chmod 775 /etc/nginx/sites-enabled").runSync()
                guard nginxOwn.succeeded == true else {
                    print("unable to change mode of nginx directories to include wiremand in group")
                    exit(11)
                }
                
                // write the upstream config
                let nginxUpstreams = try FileDescriptor.open("/etc/nginx/conf.d/upstreams.conf", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWrite, .groupRead, .otherRead])
                try nginxUpstreams.closeAfter({
                    let buildUpstream = "upstream wiremandv4 {\n\tserver 127.0.0.1:8080;\n}\nupstream wiremandv6 {\n\tserver [::1]:8080;\n}\n"
                    _ = try nginxUpstreams.writeAll(buildUpstream.utf8)
                })
     
                let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
                let daemonDBEnv = try! DaemonDB.create(directory:homeDir, publicHTTPPort: UInt16(httpPort), internalTCPPort_begin: UInt16(tcpPrintPortBegin), internalTCPPort_end: UInt16(tcpPrintPortEnd))
				try WireguardDatabase.createDatabase(environment:daemonDBEnv, wg_primaryInterfaceName:interfaceName, wg_serverPublicDomainName:endpoint!, wg_serverPublicListenPort: UInt16(wgPort), serverIPv6Block: ipv6Scope!, serverIPv4Block:ipv4Scope!, publicKey:newKeys.publicKey, defaultSubnetMask:112)
                
                let ownIt = try await Command(bash:"chown -R \(installUserName):\(installUserName) /var/lib/\(installUserName)/").runSync()
                guard ownIt.succeeded == true else {
                    fatalError("unable to change ownership of /var/lib/\(installUserName)/ directory")
                }
                
                try await CertbotExecute.acquireSSL(domain:endpoint!.lowercased())
                try NginxExecutor.install(domain:endpoint!.lowercased())
                try await NginxExecutor.reload()
                
                print(Colors.Green("[OK] - Installation complete. Please restart this machine."))
            }
            
			$0.command("domain_render_dns") {
				guard getCurrentUser() == "wiremand" else {
					fatalError("this program must be run as `wiremand` user")
				}
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
			}
            $0.command("domain_make",
                Argument<String>("domain", description:"the domain to add to the system")
            ) { domainName in
                guard getCurrentUser() == "wiremand" else {
                    fatalError("this program must be run as `wiremand` user")
                }
				let daemonDB = try DaemonDB(directory:getCurrentDatabasePath(), running:false)
                try await CertbotExecute.acquireSSL(domain: domainName.lowercased())
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
			
			$0.command("printer_authorize",
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
					print("Please enter a MAC address for this printer:")
					let allAuthorized = Dictionary(grouping:try daemonDB.printerDatabase.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("mac address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				let printerMetadata = try daemonDB.printerDatabase.authorizeMacAddress(mac:useMac!.lowercased(), subnet:useSubnet!)
				print(Colors.Green("[OK] - Printer assigned to local TCP port \(printerMetadata.port)"))
				print(Colors.Yellow("\tusername: - \(printerMetadata.username)"))
				print(Colors.Yellow("\tpassword: - \(printerMetadata.password)"))
			}
			
			$0.command("client_revoke",
			   Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
			   Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
			) { subnet, name in
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
						case 1:
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
                let newKeys = try await WireguardExecutor.generate()
                
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
                let securityKey = try daemonDB.wireguardDatabase.serveConfiguration(buildKey, forPublicKey:usePublicKey!).addingPercentEncoding(withAllowedCharacters:.alphanumerics)!
                let subnetHash = try WiremanD.hash(domain:useSubnet!).addingPercentEncoding(withAllowedCharacters:.alphanumerics)!
                let buildURL = "\nhttps://\(useSubnet!)/wg_getkey?dk=\(subnetHash)&sk=\(securityKey)&pk=\(usePublicKey!.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)\n"
                print("\(buildURL)")
            }
            
            $0.command("run") {
                enum Error:Swift.Error {
                    case handshakeCheckError
                }
                guard getCurrentUser() == "wiremand" else {
                    fatalError("this function must be run as the wiremand user")
                }
                let dbPath = getCurrentDatabasePath()
                let daemonDB = try DaemonDB(directory:dbPath, running:true)
                let interfaceName = try daemonDB.wireguardDatabase.primaryInterfaceName()
				let tcpPortBind = try daemonDB.wireguardDatabase.getServerIPv4Network().address.string
                try daemonDB.launchSchedule(.latestWireguardHandshakesCheck, interval:10, { [wgdb = daemonDB.wireguardDatabase] in
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
                        // save the handshake data to the database
                        let removeDatabase = try wgdb.processHandshakes(handshakes, zeros:zeros)
                        for curRemove in removeDatabase {
                            try? await WireguardExecutor.uninstall(publicKey:curRemove, interfaceName:interfaceName)
                        }
						if (removeDatabase.count > 0) {
							try? await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
						}
                    } catch let error {
                        print("task error: \(error)")
                    }
                })
				var allPorts = [UInt16:TCPServer]()
				try! await daemonDB.printerDatabase.assignPortHandlers(opener: { newPort in
					let newServer = try TCPServer(host:tcpPortBind, port:newPort)
					print(Colors.Magenta("{PRINT} - a new port has been opened \(newPort)"))
					allPorts[newPort] = newServer
				}, closer: { oldPort in
					allPorts[oldPort] = nil
				})
				let webserver = try PublicHTTPWebServer(wgDatabase:daemonDB.wireguardDatabase, pp:daemonDB.printerDatabase, port:daemonDB.getPublicHTTPPort())
                try webserver.run()
                webserver.wait()
            }
			$0.command("run_tcp") {
				let myServer = try TCPServer(host:"127.0.0.1", port:9100)
				while Task.isCancelled == false {
					try await Task.sleep(nanoseconds: 500000000)
				}
			}
        }.run()
    }
}
