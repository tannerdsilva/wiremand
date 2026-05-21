import Testing
import Foundation
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
