import Foundation
import Hummingbird

class PublicHTTPWebServer {
    let ipv4Application:HBApplication
    let ipv6Application:HBApplication
    
    fileprivate let wgAPI:Wireguard_MakeKeyResponder
    
    init(wgDatabase:WireguardDatabase, port:UInt16) throws {
        let wgapi = try Wireguard_MakeKeyResponder(wg_db:wgDatabase)
        let v4 = HBApplication(configuration:.init(address:.hostname("127.0.0.1", port:Int(port))))
        let v6 = HBApplication(configuration:.init(address:.hostname("::1", port:Int(port))))
        self.ipv6Application = v6
        self.ipv4Application = v4
        self.wgAPI = wgapi
    }
    
    func run() throws {
        ipv6Application.router.add("wg_makekey", method:.GET, responder:wgAPI)
        ipv4Application.router.add("wg_makekey", method:.GET, responder:wgAPI)
        try ipv4Application.start()
        try ipv6Application.start()
    }
    
    func wait() {
        ipv6Application.wait()
        ipv4Application.wait()
    }
}

fileprivate struct Wireguard_MakeKeyResponder:HBResponder {
    let wgDatabase:WireguardDatabase
    let wgServerPort:UInt16
    
    init(wg_db:WireguardDatabase) throws {
        self.wgDatabase = wg_db
        self.wgServerPort = try wg_db.getPublicListenPort()
    }
    
    public func respond(to request:HBRequest) -> EventLoopFuture<HBResponse> {
        do {
            // check which domain the user is requesting from
            guard let domainString = request.headers["Host"].first?.lowercased() else {
                request.logger.error("no host was found in the uri")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            // hash the domain
            let httpDomainHash = try WiremanD.hash(domain:domainString)

            // validate that a security key was provided
            guard let securityKey = request.uri.queryParameters["sk"] else {
                request.logger.error("no security key provided")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            // validate tha ta domain key was provided
            guard let inputDomainHash = request.uri.queryParameters["dk"] else {
                request.logger.error("no domain key provided")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            // validate that the provided domain key matches the domain key that was generated from the host header of this HTTP request
            guard httpDomainHash == inputDomainHash else {
                request.logger.error("input domain hash does not match the domain hash that was derrived from the host header.")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            // validate the security key for the given domain hash in the database
            guard try wgDatabase.validateSecurity(dk:inputDomainHash, sk:securityKey) == true else {
                request.logger.error("domain + security validation failed")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            // validate that the host name is provided
            guard let keyName = request.uri.queryParameters["key_name"] else {
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            // begin the async work of making the key
            let keyPromise = request.eventLoop.makePromise(of:HBResponse.self)
            keyPromise.completeWithTask({ [wgdb = wgDatabase] in
                // we will make the keys on behalf of the client
                let newKeys = try await WireguardExecutor.generate()
                
                let newClientAddress = try wgdb.clientMake(name:keyName, publicKey:newKeys.publicKey, subnet:domainString)
                
                let (wg_dns_name, wg_port, wg_internal_network, pubKey, interfaceName) = try wgdb.getWireguardConfigMetas()
                
                var buildKey = "[Interface]\n"
                buildKey += "PrivateKey = " + newKeys.privateKey + "\n"
                buildKey += "Address = " + newClientAddress.string + "/128\n"
                buildKey += "DNS = " + wg_internal_network.address.string + "\n"
                buildKey += "[Peer]\n"
                buildKey += "PublicKey = " + pubKey + "\n"
                buildKey += "PresharedKey = " + newKeys.presharedKey + "\n"
                buildKey += "AllowedIPs = " + wg_internal_network.cidrString + "\n"
                buildKey += "Endpoint = " + wg_dns_name + ":\(wg_port)" + "\n"
                buildKey += "PersistentKeepalive = 25" + "\n"
                
                var buildBytes = ByteBuffer()
                buildBytes.writeString(buildKey)
                
                try await WireguardExecutor.install(key:newKeys, address:newClientAddress, interfaceName:interfaceName)
                return HBResponse(status: .ok, body:.byteBuffer(buildBytes))
            })
            return keyPromise.futureResult
        } catch let error {
            request.logger.error("error thrown - \(error)")
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
