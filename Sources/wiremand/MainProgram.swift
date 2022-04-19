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
                let newKeys = try await WireguardExecutor.generateNewKey()
                
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
                    buildConfig += "bind-interfaces\n"
                    buildConfig += "server=::1\n"
                    buildConfig += "server=127.0.0.1\n"
                    buildConfig += "user=wiremand\n"
                    buildConfig += "group=wiremand\n"
                    try dnsMasqConfFile.writeAll(buildConfig.utf8)
                })
                
                print("making user `wiremand`...")
                
                // make the user
                let makeUser = try await Command(bash:"useradd -md /var/lib/wiremand -U -G www-data wiremand").runSync()
                guard makeUser.succeeded == true else {
                    print("unable to create `wiremand` user on the system")
                    exit(8)
                }
                
                // get the uid and gid of our new user
                guard let getUsername = getpwnam("wiremand") else {
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
                
                guard whichWg.count > 0 && whichWg.contains("/") == true && whichWgQuick.count > 0 && whichWgQuick.contains("/") == true else {
                    print("unable to locate `wg` and `wg-quick`")
                    exit(9)
                }

                print("installing soduers modifications for `wiremand` user...")
                
                // add the sudoers modifications for this user
                let sudoersFD = try FileDescriptor.open("/etc/sudoers.d/wiremand", .writeOnly, options:[.create, .truncate], permissions: [.ownerRead, .groupRead])
                try sudoersFD.closeAfter({
                    var sudoAddition = "wiremand ALL = NOPASSWD: \(whichWg)\n"
                    sudoAddition += "wiremand ALL = NOPASSWD: \(whichWgQuick)\n"
                    sudoAddition += "wiremand ALL = NOPASSWD: \(whichCertbot)\n"
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
                    buildConfig += "User=wiremand\n"
                    buildConfig += "Group=wiremand\n"
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
                var nginxOwn = try await Command(bash:"chown root:wiremand /etc/nginx && chown root:wiremand /etc/nginx/conf.d && chown root:wiremand /etc/nginx/sites-enabled").runSync()
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
                let nginxUpstreams = try FileDescriptor.open("/etc/nginx/conf.d/upstreams", .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWrite, .groupRead, .otherRead])
                try nginxUpstreams.closeAfter({
                    var buildUpstream = "upstream wiremandv4 {\n\tserver 127.0.0.1:8080;\n}\nupstream wiremandv6 {\n\tserver [::1]:8080;\n}\n"
                    try nginxUpstreams.writeAll(buildUpstream.utf8)
                })
                
                print("\(setgid(getUsername.pointee.pw_gid))")
                print("\(setuid(getUsername.pointee.pw_uid))")
                
                let homeDir = URL(fileURLWithPath:"/var/lib/wiremand/")
                let daemonDB = try! DaemonDB.create(directory:homeDir, publicHTTPPort: UInt16(httpPort), internalTCPPort_begin: UInt16(tcpPrintPortBegin), internalTCPPort_end: UInt16(tcpPrintPortEnd))
                let wgDB = try! WireguardDatabase.createDatabase(directory: homeDir, wg_primaryInterfaceName:interfaceName, wg_serverPublicDomainName:endpoint!, wg_serverPublicListenPort: UInt16(wgPort), serverIPv6Block: ipv6Scope!, publicKey:newKeys.publicKey, defaultSubnetMask:112)
            }
            
            $0.command("make_domain",
                Argument<String>("domain", description:"the domain to add to the system")
            ) { domainName in
                guard getCurrentUser() == "wiremand" else {
                    fatalError("this program must be run as `wiremand` user")
                }
                let wgDB = try WireguardDatabase(directory:getCurrentDatabasePath())
                print("database opened")
            }
            
            $0.command("run") {
                print("running daemon...")
                exit(5)
            }
        }.run()
    }
}
