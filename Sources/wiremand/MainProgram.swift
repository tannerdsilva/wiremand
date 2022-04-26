import Foundation
import Commander
import AddressKit
import SystemPackage
import SwiftSlash

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
               Option<Int>("private_tcpPrintPort_end", default:10100)
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
                    let makeLine = "net.ipv6.conf.all.forwarding=1\n"
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
                let daemonDB = try! DaemonDB.create(directory:homeDir, publicHTTPPort: UInt16(httpPort), internalTCPPort_begin: UInt16(tcpPrintPortBegin), internalTCPPort_end: UInt16(tcpPrintPortEnd))
                let wgDB = try! WireguardDatabase.createDatabase(directory: homeDir, wg_primaryInterfaceName:interfaceName, wg_serverPublicDomainName:endpoint!, wg_serverPublicListenPort: UInt16(wgPort), serverIPv6Block: ipv6Scope!, publicKey:newKeys.publicKey, defaultSubnetMask:112)
                
                let ownIt = try await Command(bash:"chown -R \(installUserName):\(installUserName) /var/lib/\(installUserName)/").runSync()
                guard ownIt.succeeded == true else {
                    fatalError("unable to change ownership of /var/lib/\(installUserName)/ directory")
                }
                
                print(Colors.Green("[OK] - Installation complete. Please restart this machine."))
            }
            
            $0.command("domain_make",
                Argument<String>("domain", description:"the domain to add to the system")
            ) { domainName in
                guard getCurrentUser() == "wiremand" else {
                    fatalError("this program must be run as `wiremand` user")
                }
                let wgDB = try WireguardDatabase(directory:getCurrentDatabasePath())
                try await CertbotExecute.acquireSSL(domain: domainName.lowercased())
                try NginxExecutor.install(domain: domainName.lowercased())
                try await NginxExecutor.reload()
                let (newSubnet, newSK) = try wgDB.subnetMake(name:domainName.lowercased())
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
                let wgDB = try WireguardDatabase(directory:getCurrentDatabasePath())
                let allDomains = try wgDB.allSubnets()
                for curDomain in allDomains {
                    print("\(curDomain.name)")
                    print(Colors.Yellow("\t- sk: \(curDomain.securityKey)"))
                    print(Colors.Cyan("\t- dk: \(try WiremanD.hash(domain:curDomain.name))"))
                    print(Colors.dim("\t- subnet: \(curDomain.network.cidrString)"))
                }
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
                try daemonDB.launchSchedule(.latestWireguardHandshakesCheck, interval:2, {
                    print("this is a test task fire \(Date())")
                })
                Task.detached {
                    try await Task.sleep(nanoseconds: 1000000000 * 12)
                    print("canceling task")
                    try daemonDB.cancelSchedule(.latestWireguardHandshakesCheck)
                    print("canceled task yay")
                }
                /*let handshakeValidationTask = DBScheduledTask(daemonDB:daemonDB, scheduledTask: .latestWireguardHandshakesCheck, { [interfaceName] in
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
                    let removeDatabase = try daemonDB.wireguardDatabase.processHandshakes(handshakes, zeros:zeros)
                    for curRemove in removeDatabase {
                        try? await WireguardExecutor.uninstall(publicKey:curRemove, interfaceName:interfaceName)
                    }
                })*/
                
                let webserver = try PublicHTTPWebServer(wgDatabase:daemonDB.wireguardDatabase, port:daemonDB.getPublicHTTPPort())
                try webserver.run()
                webserver.wait()
                exit(5)
            }
        }.run()
    }
}
