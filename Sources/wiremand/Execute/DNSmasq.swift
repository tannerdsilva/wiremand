import SystemPackage
import Foundation
import SwiftSlash

extension WireguardDatabase.ClientInfo {
	func dynamicDNSLine() -> String {
		let domainName = self.subnetName.split(separator:".", omittingEmptySubsequences:false)
		let mainName:String
		if domainName.count == 3 {
			mainName = self.name + "." + domainName[1] + ".wg"
		} else {
			mainName = self.name + "." + self.subnetName + ".wg"
		}
		var mainLine = self.address.string + "\t" + mainName + "\n"
		if addressV4 != nil {
			mainLine += self.addressV4!.string + "\t" + mainName + "\n"
		}
		return mainLine
	}
}

struct DNSmasqExecutor {
	enum Error:Swift.Error {
		case reloadError
	}
	static func exportAutomaticDNSEntries(db:DaemonDB) throws {
		let clients = try db.wireguardDatabase.allClients().compactMap { $0.dynamicDNSLine() }.joined(separator: "\n")
		// install the systemd service for the daemon
		let systemdFD = try FileDescriptor.open("/var/lib/wiremand/hosts-auto", .writeOnly, options:[.create, .truncate], permissions:[.ownerRead, .ownerWrite, .groupRead, .groupWrite])
		_ = try systemdFD.closeAfter({
			try systemdFD.writeAll(clients.utf8)
		})
	}
	static func reload() async throws {
		guard try await Command(bash:"sudo systemctl reload dnsmasq").runSync().succeeded == true else {
			throw Error.reloadError
		}
	}
}
