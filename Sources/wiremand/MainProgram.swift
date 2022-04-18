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
        return getCurrentDatabasePath(home:URL(fileURLWithPath:String(cString:getpwuid(getuid())!.pointee.pw_dir)))
    }
    static func getCurrentDatabasePath(home:URL) -> URL {
        return home.appendingPathComponent("wiremand-dbi")
    }

    static func main() async throws {
        await AsyncGroup {
            $0.command("install",
               Option<String>("interfaceName", default:"wg2930"),
               Option<String>("user", default:"wiremand"),
               Option<Int>("wg_port", default:29300),
               Option<Int>("public_httpPort", default:8080),
               Option<Int>("private_tcpPrintPort_start", default:9100)
            ) { interfaceName, installUserName, wgPort, httpPort, tcpPrintPort in
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
                let installCommand = try await Command(bash:"apt-get update && apt-get install wireguard dnsmasq -y").runSync()
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
                    buildConfig += "server=2606:4700:4700::1111\n"
                    buildConfig += "server=2606:4700:4700::1001\n"
                    buildConfig += "server=1.1.1.1\n"
                    buildConfig += "server=1.0.0.1\n"
                    try dnsMasqConfFile.writeAll(buildConfig.utf8)
                })
                
                print("making user `wiremand`...")
                
                // make the user
                let makeUser = try await Command(bash:"useradd -md /var/lib/wiremand wiremand").runSync()
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
                
                print("determining wg paths...")
                
                // find wireguard and wg-quick
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
                let systemdFD = try FileDescriptor.open("/etc/systemd/system/wiremand.service", .writeOnly, options:[.create], permissions:[.ownerRead, .ownerWrite, .groupRead, .otherRead])
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
            }
            
            $0.command("make_domain",
                Argument<String>("domain", description:"the domain to add to the system")
            ) { domainName in
                
//                let wireguardDatabase =
            }
            
            $0.command("run") {
                print("running daemon...")
                exit(5)
            }
        }.run()
    }
}
