import Foundation
import Hummingbird
import HummingbirdTLS
import NIO
import NIOSSL
import Logging
import QuickLMDB
import ServiceLifecycle
import wiremand_databases

extension PublicHTTPWebServer {
	/// the http server context used for the apiv2 web server
	public struct Context:RequestContext {
		/// required by Hummingbird to provide the core request context storage.
		public var coreContext:Hummingbird.CoreRequestContextStorage
		/// the SwiftNIO ByteBuffer allocator used to produce responses.
		public let allocator:ByteBufferAllocator
		/// the primary initializer for the context.
		public init(source:Hummingbird.ApplicationRequestContextSource) {
			coreContext = .init(source:source)
			allocator = source.channel.allocator
		}
	}
}

/// Hosts the secure web server for external inbound network traffic.
/// Security comes from the self-signed SSL certificate.
/// The server is hosted on a IPv4 address and IPv6 address.
/// Routes:
/// - wg_makekey: A POST method for creating a new client.
/// - wg_getkey: A GET method for getting a clients public key.
public final actor PublicHTTPWebServer: Service {
	let appv4: Application<RouterResponder<Context>>
	let appv6: Application<RouterResponder<Context>>
	
	init(eventLoop: EventLoopGroupProvider, wgdb: WireguardDatabase, hostIPv6: String, hostIPv4: String, port: UInt16) throws {
		let logLevel: Logger.Level
		#if DEBUG
		logLevel = .trace
		#else
		logLevel = .error
		#endif

		let certPath = "/etc/wiremand/ssl/fullchain.pem"
		let keyPath  = "/etc/wiremand/ssl/privkey.pem"

        let certificateChain = try NIOSSLCertificate.fromPEMFile(certPath)
        let privateKey = try NIOSSLPrivateKey(file: keyPath, format: .pem)
        let tlsConfig =  TLSConfiguration.makeServerConfiguration(certificateChain: certificateChain.map { .certificate($0) }, privateKey: .privateKey(privateKey))

		let bindAddressV4 = BindAddress.hostname(hostIPv4, port: Int(port))
		let appConfigurationV4 = Hummingbird.ApplicationConfiguration(address: bindAddressV4, reuseAddress: true)

		let makeRouter = Router(context: Context.self)
		let wgapi = try Wireguard_MakeKeyResponder(db: wgdb)
		let wgget = Wireguard_GetKeyResponder(db: wgdb)

		makeRouter.on("wg_makekey", method: .post, responder: wgapi)
		makeRouter.on("wg_getkey", method: .get, responder: wgget)

		self.appv4 = Application(router: makeRouter, server: try .tls(.http1(), tlsConfiguration: tlsConfig), configuration: appConfigurationV4, eventLoopGroupProvider: eventLoop)

		let bindAddressV6 = BindAddress.hostname(hostIPv6, port: Int(port))
		let appConfigurationV6 = Hummingbird.ApplicationConfiguration(address: bindAddressV6, reuseAddress: true)
		self.appv6 = Application(router: makeRouter, server: try .tls(.http1(), tlsConfiguration: tlsConfig), configuration: appConfigurationV6, eventLoopGroupProvider: eventLoop)
	}
	
	public func run() async throws {
		try await withThrowingTaskGroup(of: Void.self) { tg in
			tg.addTask { [app = appv4] in
				try await app.run()
			}
			tg.addTask { [app = appv6] in
				try await app.run()
			}
			_ = try await tg.next()
		}
	}
}


extension PublicHTTPWebServer {
	fileprivate struct Wireguard_GetKeyResponder:HTTPResponder {
		let logger = Logger(label: "Wireguard.GetKeyResponder")
		let wgdb:WireguardDatabase
		
		init(db:WireguardDatabase) {
			wgdb = db
		}
		
		public func respond(to request:borrowing Request, context: Context) async throws -> Response {
			guard let inputDomain = request.uri.queryParameters["domain"] else {
				logger.error("no domain")
				return Response(status: .badRequest)
			}
			let host = EncodedString(String(inputDomain))
			
			let httpDomainHash: DomainHash
			do {
				httpDomainHash = try DomainHash(domainName: host)
			} catch {
				logger.error("failed to hash domain: \(error)")
				return Response(status: .badRequest)
			}
			
			guard let inputDomainHashString = request.uri.queryParameters["dk"] else {
				logger.error("no domain key provided")
				return Response(status: .badRequest)
			}
			guard let inputDomainHash = DomainHash(base64String: String(inputDomainHashString)) else {
				logger.error("dk parameter is not a valid 8-byte, Base64 encoded string")
				return Response(status: .badRequest)
			}
			
			guard httpDomainHash == inputDomainHash else {
				logger.error(
					"input domain hash does not match the domain hash derived from the host header."
				)
				return Response(status: .badRequest)
			}
			
			guard let publicKeyString = request.uri.queryParameters["pk"] else {
				logger.error("public key not provided")
				return Response(status: .badRequest)
			}
			guard let publicKey = PublicKey(argument: String(publicKeyString)) else {
				logger.error("http request public key is not a valid public key")
				return Response(status: .badRequest)
			}
			
			let config = try wgdb.getConfiguration(publicKey: publicKey, domainName: host)
				
			var writeBuffer = ByteBuffer()
			writeBuffer.writeString(String(config.configuration))
			
			return Response(status:.ok, headers:[.contentDisposition:"attachment; filename=\"\(config.name.filter({ ($0.isASCII) && ($0.isLetter || $0.isNumber) })).conf\";"], body: ResponseBody(byteBuffer: writeBuffer))
		}
	}
}

extension PublicHTTPWebServer {
	/// Handles POST requests to provision new WireGuard clients via the web API.
	/// - Query Params: `domain`, `sk` (security key), `dk` (domain hash), `key_name`, `client_public_key`
	/// - Behavior: If `key_name` already exists, removes the old client and creates a new one with the provided public key.
	/// - Response: A string containing the completed client wireguard key.
	fileprivate struct Wireguard_MakeKeyResponder:HTTPResponder {
		let logger = Logger(label: "Wireguard.MakeKeyResponder")
		let wgdb:WireguardDatabase
		let wgServerPort:UInt16
		
		init(db:WireguardDatabase) throws {
			self.wgdb = db
			self.wgServerPort = try wgdb.getPublicListenPort().RAW_native()
		}
		
		public func respond(to request: Request,context: Context) async throws -> Response {
			guard let inputDomain = request.uri.queryParameters["domain"] else {
				logger.error("no domain")
				return Response(status: .badRequest)
			}
			let host = EncodedString(String(inputDomain))
			
			let httpDomainHash: DomainHash
			do {
				httpDomainHash = try DomainHash(domainName: host)
			} catch {
				logger.error("failed to hash domain: \(error)")
				return Response(status: .badRequest)
			}
			
			guard let securityKeyString = request.uri.queryParameters["sk"] else {
				logger.error("no security key provided")
				return Response(status: .badRequest)
			}
			guard let securityKey = SecurityKey(base64String: String(securityKeyString)) else {
				logger.error("dk parameter is not a valid 512-byte, Base64 encoded string")
				return Response(status: .badRequest)
			}
			
			guard let inputDomainHashString = request.uri.queryParameters["dk"] else {
				logger.error("no domain key provided")
				return Response(status: .badRequest)
			}
			guard let inputDomainHash = DomainHash(base64String: String(inputDomainHashString)) else {
				logger.error("dk parameter is not a valid 8-byte, Base64 encoded string")
				return Response(status: .badRequest)
			}

			guard httpDomainHash == inputDomainHash else {
				logger.error(
					"input domain hash does not match the domain hash derived from the host header."
				)
				return Response(status: .badRequest)
			}
			
			guard try wgdb.validateSecurity(dk: inputDomainHash, sk: securityKey) == true else {
				logger.error("domain + security validation failed")
				return Response(status: .badRequest)
			}
			
			guard let keyNameSubstring = request.uri.queryParameters["key_name"] else {
				logger.error("key_name query parameter missing")
				return Response(status: .badRequest)
			}
			let keyName = String(keyNameSubstring)
			
			guard let publicKeyString = request.uri.queryParameters["client_public_key"] else {
				logger.error("client_public_key query parameter missing")
				return Response(status: .badRequest)
			}
			guard let clientPublicKey = PublicKey(argument: String(publicKeyString)) else {
				logger.error("provided client_public_key is not a valid 32-byte Base64 string")
				return Response(status: .badRequest)
			}
			
			let newKeys = try await WireguardExecutor.generateClient()
			
			let (wgPort, wgPrimarySubnet, pubKey, interfaceName, publicV4, _) = try wgdb.getWireguardConfigMetas()
			
			var client: (address:Address?, publicKey:PublicKey?) = (nil, nil)
			do {
				client.address = try wgdb.clientMake(name: EncodedString(keyName), publicKey: clientPublicKey, domain: host)
				client.publicKey = nil
			} catch LMDBError.keyExists {
				logger.info("client name already exists on this subnet", metadata: ["client": "\(keyName)", "subnet": "\(String(host))"])
				let removed = try wgdb.clientRemove(domain: host, name: EncodedString(keyName))
				client.publicKey = removed
				client.address = try wgdb.clientMake(name: EncodedString(keyName), publicKey: clientPublicKey, domain: host)
			}
			
			let ipAddress = client.address!.string + "\(client.address!.isV4 ? "/32" : "/128")"
			var buildKey = "Address = " + ipAddress + "\n"
			buildKey += "DNS = \(wgPrimarySubnet.addressString)\n"
			buildKey += "[Peer]\n"
			buildKey += "PublicKey = \(pubKey.string)\n"
			buildKey += "PresharedKey = \(newKeys.presharedKey)\n"
			let ipAddressSubnet = client.address!.string + "\(client.address!.isV4 ? "/24" : "/64")"
			buildKey += "AllowedIPs = \(ipAddressSubnet)\n"
			let dnsAllowedIPString = "\(wgPrimarySubnet.addressString)\(wgPrimarySubnet.isV4 ? "/32" : "/128")\n"
			buildKey += "AllowedIPs = \(dnsAllowedIPString)"
			buildKey += "Endpoint = \(publicV4.string):\(wgPort.RAW_native())\n"
			buildKey += "PersistentKeepalive = 25" + "\n"
			
			var responseBytes = ByteBuffer()
			responseBytes.writeString(buildKey)
			
			if let oldKey = client.publicKey {
				try await WireguardExecutor.uninstall(publicKey:oldKey, interfaceName:interfaceName)
			}
			try await WireguardExecutor.install(publicKey:clientPublicKey, presharedKey:newKeys.presharedKey, addresses:[client.address!], interfaceName:interfaceName)
			try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
			try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName, logLevel: logger.logLevel)
			try await DNSmasqExecutor.reload()
			return Response(status: .ok, body: ResponseBody(byteBuffer: responseBytes))
		}
	}
}
