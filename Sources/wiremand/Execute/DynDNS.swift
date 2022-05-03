import SystemPackage
import Foundation

extension WireguardDatabase.ClientInfo {
	func dynamicDNSLine() -> String {
		let domainName = self.subnetName.split(separator:".", omittingEmptySubsequences:false)
		let mainName:String
		if domainName.count == 3 {
			mainName = self.name + "." + domainName[1] + ".wg"
		} else {
			mainName = self.name + "." + self.subnetName + ".wg"
		}
		var mainLine = mainName + "\t" + self.address.string + "\n"
		if addressV4 != nil {
			mainLine += mainName + "\t" + self.addressV4!.string + "\n"
		}
		return mainLine
	}
}

struct DynDNS {
	static func exportAutomaticDNSEntries(db:DaemonDB) throws {
		let clients = try db.wireguardDatabase.allClients().compactMap { $0.dynamicDNSLine() }.joined(separator: "\n")
		// install the systemd service for the daemon
		let systemdFD = try FileDescriptor.open("/var/lib/wiremand/hosts-auto", .writeOnly, options:[.create, .truncate], permissions:[.ownerRead, .ownerWrite, .groupRead, .groupWrite])
		try systemdFD.closeAfter({
			try systemdFD.writeAll(clients.utf8)
		})
	}
}
