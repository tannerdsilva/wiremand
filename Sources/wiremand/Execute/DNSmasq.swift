import SystemPackage
import Foundation
import SwiftSlash
import wiremand_databases

extension WireguardDatabase.ClientInfo {
	/// Creates the DNS string for a Client's name and all of 
	/// the addresses for the domains of the client.
	public func dynamicDNSLine() -> String {
		var lines = [String]()
		for (domain, address) in self.domains {
			let domainName = String(self.name).split(separator:".", omittingEmptySubsequences:false)
			let mainName:String
			if domainName.count == 3 {
				mainName = String(self.name) + "." + domainName[1] + ".wg"
			} else {
				mainName = String(self.name) + "." + String(domain) + ".wg"
			}
			lines.append("\(address.string)\t\(mainName)\n")
		}
		let mainLine = lines.joined()
		return mainLine
	}
}

struct DNSmasqExecutor {
	public enum Error:Swift.Error {
		case reloadError
	}
	/// Exports the DNS entries for each client in the database.
	/// Creates the DNS mapping of `clientName.domainName.wg` to the client address.
	/// Exports the DNS entries into the /var/lib/username/hosts-auto file.
	public static func exportAutomaticDNSEntries(db:WireguardDatabase) throws {
		let clients = try db.allClients().compactMap { $0.dynamicDNSLine() }.joined(separator: "\n")
		// install the systemd service for the daemon
		let systemdFD = try FileDescriptor.open("/var/lib/wiremand/hosts-auto", .writeOnly, options:[.create, .truncate], permissions:[.ownerRead, .ownerWrite, .groupRead, .groupWrite])
		_ = try systemdFD.closeAfter({
			try systemdFD.writeAll(clients.utf8)
		})
	}
	static func reload() async throws {
		// Signal dnsmasq to re-read its config and hosts files with SIGHUP.
		// We avoid `systemctl reload dnsmasq` here because the daemon runs as
		// the unprivileged `wiremand` user: systemd control is not reachable via
		// capabilities, but dnsmasq runs as the same `wiremand` user (set in
		// /etc/dnsmasq.conf), so a same-UID SIGHUP is permitted. Use `-x` to
		// match the exact process name and `-o` to require at least one match.
		guard try await Command(sh: "pkill -HUP -x -o dnsmasq", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
			throw Error.reloadError
		}
	}
}
