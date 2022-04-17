import Foundation
import Hummingbird

class PublicHTTPWebServer {
    let ipv4Application:HBApplication
    let ipv6Application:HBApplication
    
    let wgAPI:WireguardHTTPHandler
    
    init(wgDatabase:WireguardDatabase, port:Int) throws {
        let wgapi = try WireguardHTTPHandler(wg_db:wgDatabase)
        let v4 = HBApplication(configuration:.init(address:.hostname("127.0.0.1", port:port)))
        let v6 = HBApplication(configuration:.init(address:.hostname("::1", port:port)))
        self.ipv6Application = v6
        self.ipv4Application = v4
        self.wgAPI = wgapi
    }
    
    func run() throws {
//        ipv6Application.router.add("wg_addpeer", method:.POST, responder:wgAPI)
//        ipv4Application.router.add("wg_addpeer", method:.POST, responder:wgAPI)
        
        ipv6Application.router.add("wg_makekey", method:.GET, responder:wgAPI)
        ipv4Application.router.add("wg_makekey", method:.GET, responder:wgAPI)
        
//        ipv6Application.router.add("wg_updatekey", method:.POST, responder:wgAPI)
//        ipv4Application.router.add("wg_updatekey", method:.POST, responder:wgAPI)
    }
}

//handles the requests
public class WireguardHTTPHandler:HBResponder {
    let wgDatabase:WireguardDatabase
    let wgServerPort:UInt16
    
    init(wg_db:WireguardDatabase) throws {
        self.wgDatabase = wg_db
        self.wgServerPort = try wg_db.getPublicListenPort()
    }
    
    public func respond(to request:HBRequest) -> EventLoopFuture<HBResponse> {
        do {
            // parse the paths
            let paths = request.uri.path.split(separator:"/", omittingEmptySubsequences:true)
            
            // unpack the domain from the HTTP data
            guard let domainString = request.uri.host?.lowercased(),
                  let domainData = domainString.data(using:.utf8) else {
                request.logger.error("unable to extract http host and export with .utf8")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            let httpDomainHash = try Blake2bHasher.hash(data:domainData, length:64)
            let httpDomainHashB64 = httpDomainHash.base64EncodedString()
            
            // extract the provided domain hash
            guard paths.count > 1, let inputDomainHashB64 = paths[1].removingPercentEncoding else {
                request.logger.error("no ")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            
            // validate that the http domain hash is the same as the provided domain hash
            guard httpDomainHashB64 == inputDomainHashB64 else {
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            
            // validate that the host name is provided
            guard let keyName = request.uri.queryParameters["key_name"] else {
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            
            switch paths[0].lowercased() {
                case "wg_makekey":
                let keyPromise = request.eventLoop.makePromise(of:HBResponse.self)
                keyPromise.completeWithTask({ [wgdb = wgDatabase] in
                    // we will make the keys on behalf of the client
                    let newKeys = try await WireguardExecutor.generateNewKey()
                    let newClientAddress = try wgdb.clientMake(name:keyName, publicKey:newKeys.publicKey, subnet:domainString)
                    let (wg_dns_name, wg_port, wg_internal_network, pubKey) = try wgdb.getWireguardConfigMetas()
                    
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
                    return HBResponse(status: .ok)
                })
                return keyPromise.futureResult
                case "wg_updatekey":
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
                default:
                    return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            
        } catch let error {
            request.logger.error("error thrown - \(error)")
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
