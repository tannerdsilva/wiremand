import SystemPackage
import Foundation
import SwiftSlash
import wiremand_databases

extension WireguardDatabase.ClientInfo {
	public func dynamicDNSLine() -> String {
		let domainName = self.domainName.split(separator:".", omittingEmptySubsequences:false)
		let mainName:String
		if domainName.count == 3 {
			mainName = self.name + "." + domainName[1] + ".wg"
		} else {
			mainName = self.name + "." + String(self.domainName) + ".wg"
		}
		let v6Lines = self.address.map { $0.string + "\t" + mainName + "\n" }
		var mainLine = v6Lines.joined()
		if addressV4 != nil {
			mainLine += self.addressV4!.string + "\t" + mainName + "\n"
		}
		return mainLine
	}
}

struct DNSmasqExecutor {
	public enum Error:Swift.Error {
		case reloadError
	}
	public static func exportAutomaticDNSEntries(db:WireguardDatabase) throws {
		let clients = try db.allClients().compactMap { $0.dynamicDNSLine() }.joined(separator: "\n")
		// install the systemd service for the daemon
		let systemdFD = try FileDescriptor.open("/var/lib/wiremand/hosts-auto", .writeOnly, options:[.create, .truncate], permissions:[.ownerRead, .ownerWrite, .groupRead, .groupWrite])
		_ = try systemdFD.closeAfter({
			try systemdFD.writeAll(clients.utf8)
		})
	}
	static func reload() async throws {
		guard try await Command(sh: "sudo systemctl reload dnsmasq", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
			throw Error.reloadError
		}
	}
}
