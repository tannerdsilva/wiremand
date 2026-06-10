import Testing
import Foundation
import SwiftSlash
import wiremand_databases
import wiremand
import Logging
import bedrock
import RAW

@Suite("wiremand tests", .serialized)
struct WiremandTests {}

extension WiremandTests {
  @Suite("WDGB Tests", .serialized)
  struct WGDBTests {
    @Test func testDomainMake() throws {

      let path = FileManager.default.homeDirectoryForCurrentUser.path
      WireguardDatabase.deleteDB(base: Path(path))
      let wgdb = try WireguardDatabase(base: Path(path), logLevel: .info)
      let publicKey = PublicKey(argument: "OO+P8R1Q2WewkZNjFvuTECqWzJPYiIc+PCUW9EFVEBg=")!
			try wgdb.install(wg_primaryInterfaceName: EncodedString("exampleInterface"), wg_serverPublicDomainName: EncodedString("exampleDomainName"), wg_resolvedServerPublicIPv4: AddressV4("127.0.0.1")!, wg_resolvedServerPublicIPv6: AddressV6("::1")!, wg_serverPublicListenPort: EncodedUInt16(RAW_native: 2930), serverIPv6Block: NetworkV6("1111:1111:1111:1111::/64")!, serverIPv6BlockName: EncodedString("host_block"), serverIPv4Block: NetworkV4("0.0.0.0/24")!, publicKey: publicKey, defaultDomainMask: RAW_byte(RAW_native: 112))
      try wgdb.domainMake(name: EncodedString("exampleDomain"))
      let domains = try wgdb.allDomains()
      let clientPublicKey = PublicKey(argument: "6/2xMdtO+AZD5X0dzma03aUvgTh04O+uHDGpRVkzxQY=")!

      let clientName = try ClientNameHash(clientName: EncodedString("someName"))
      print(clientName)
      try wgdb.clientMake(name: EncodedString("newClient"), publicKey: clientPublicKey, domain: EncodedString("exampleDomain"))
      let bool = try wgdb.validateNewClientName(domain: EncodedString("exampleDomain"), clientName: EncodedString("invalid"))
      print(bool)
    }
  }
}

extension WiremandTests {
  @Suite("Netlink Tests", .serialized)
  struct NetlinkTests {
    @Test func testGetInterface() async throws {
      let interfaces = try RTNetlink.getInterfaces()
      let sortedInterfaces = Array(interfaces).sorted { $0.interfaceIndex < $1.interfaceIndex }

      let result = try await Command(sh: "ip link show", environment: CurrentEnvironment.environmentVariables()).runSync()
      guard result.succeeded == true else {
        print("failed command")
        throw fatalError()
      }

      #expect(interfaces.count == result.stdout.count / 2)

      for res in result.stdout {
        print(String(data:Data(res), encoding:.utf8)!)
      }

      for iface in sortedInterfaces {
        print("""
        • \(iface.interfaceName) (index: \(iface.interfaceIndex))
          MAC: \(iface.address ?? "N/A")
          Broadcast: \(iface.broadcast ?? "N/A")
        """)
      }
    }

    @Test func testGetAddress() throws {
      let addressesV4 = try RTNetlink.getAddressesV4()
      for addr in addressesV4 {
        let scopeDesc = switch addr.scope {
          case 0: "UNIVERSE"
          case 1: "LINK"
          case 255: "HOST"
          default: "UNKNOWN(\(addr.scope))"
        }
        print("  \(addr.interfaceName): \(addr.address ?? "nil")/\(addr.prefix_length) [scope: \(scopeDesc)]")
      }

      let addressesV6 = try RTNetlink.getAddressesV6()
      for addr in addressesV6 {
        print("  \(addr.interfaceName): \(addr.address ?? "nil")/\(addr.prefix_length)")
      }
    }

    @Test func testGetRoutes() throws {
      let routesV4 = try RTNetlink.getRoutesV4()
      for route in routesV4 {
        let dst = route.destination ?? "*"
        let gw = route.gateway ?? "*"
        let iif = route.inputInterfaceName ?? "-"
        let oif = route.outputInterfaceName ?? "-"
        print("  \(dst) via \(gw) dev \(oif) (iif: \(iif)) table: \(route.table)")
      }

      let routesV6 = try RTNetlink.getRoutesV6()
      for route in routesV6 {
        let dst = route.destination ?? "*"
        let gw = route.gateway ?? "*"
        let iif = route.inputInterfaceName ?? "-"
        let oif = route.outputInterfaceName ?? "-"
        print("  \(dst) via \(gw) dev \(oif) (iif: \(iif)) table: \(route.table)")
      }
    }

    @Test func testGetDefaultRoutes() throws {
      let routesV4 = try RTNetlink.getRoutesV4()
      let defaultV4 = routesV4.filter { $0.destination_length == 0 }
      for route in defaultV4 {
        let dst = route.destination ?? "*"
        let gw = route.gateway ?? "*"
        let iif = route.inputInterfaceName ?? "-"
        let oif = route.outputInterfaceName ?? "-"
        let src = route.source ?? "-"
        print("  \(dst) via \(gw) dev \(oif) (iif: \(iif)) table: \(route.table) src: \(src)")
      }

      let routesV6 = try RTNetlink.getRoutesV6()
      let defaultV6 = routesV6.filter { $0.destination_length == 0 }
      for route in defaultV6 {
        let dst = route.destination ?? "*"
        let gw = route.gateway ?? "*"
        let iif = route.inputInterfaceName ?? "-"
        let oif = route.outputInterfaceName ?? "-"
        let src = route.source ?? "-"
        print("  \(dst) via \(gw) dev \(oif) (iif: \(iif)) table: \(route.table) src: \(src)")
      }
    }

    @Test func getDefaultRoutes() throws {
      let routesV4 = try RTNetlink.getRoutesV4()
      let defaultV4 = routesV4.filter { $0.destination_length == 0 }.first!
      print(defaultV4.source!)

      let addressV6 = try RTNetlink.getAddressesV6()
      let addressV6Sorted = addressV6.sorted { $0.address! < $1.address! }
      for address in addressV6Sorted {
        print("-----------------------")
        print(address.address!)
        if (address.flags.isDeprecated) { print("Depreciated") }
        if (address.flags.isEphemeral) { print("Ephemeral") }
        if (address.flags.isManagementTemporary) { print("Mngtmpaddr") }
        if (address.flags.isNoprefixroute) { print("noprefixroute") }
        if (address.flags.isSecondary) { print("Secondary") }
        if (address.flags.isStablePrivacy) { print("stable privacy") }
        if (address.flags.isTentative) { print("Tentative") }
        if (address.flags.isEmpty) { print("Empty") }
      }
      let filteredV6 = addressV6.filter { $0.interfaceName == defaultV4.outputInterfaceName && $0.scope == 0 && !($0.flags.contains(.temporary))}
      // let defaultV6 = filteredV6.first!
      // print(defaultV6.address!)
    }
  }
}
