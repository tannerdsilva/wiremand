import Foundation
import Hummingbird
import NIOFoundationCompat
import Logging
import AddressKit
import QuickLMDB

extension String {
	fileprivate func makeAuthData() -> PrintDB.AuthData? {
		guard self.contains(" ") == true else {
			return nil
		}
		let splitSpace = self.split(separator:" ", omittingEmptySubsequences:false)
		guard splitSpace.count == 2, splitSpace[0] == "Basic", let decodedData = Data(base64Encoded:String(splitSpace[1])), let decodedString = String(data:decodedData, encoding:.utf8), decodedString.contains(":") else {
			return nil
		}
		
		let splitAuthPlain = decodedString.split(separator:":", omittingEmptySubsequences:false)
		guard splitAuthPlain.count == 2 else {
			print(Colors.Red("\t unable to split"))
			return nil
		}
		return PrintDB.AuthData(un:String(splitAuthPlain[0]), pw:String(splitAuthPlain[1]))
	}
}

class PublicHTTPWebServer {
    let ipv4Application:HBApplication
    let ipv6Application:HBApplication
    
    fileprivate let wgAPI:Wireguard_MakeKeyResponder
    fileprivate let wgGetKey:Wireguard_GetKeyResponder
	fileprivate let pp:PrinterPoll
	
	init(daemonDB:DaemonDB, pp:PrintDB, port:UInt16) throws {
		let wgapi = try Wireguard_MakeKeyResponder(ddb:daemonDB)
        let wgget = Wireguard_GetKeyResponder(wg_db: daemonDB.wireguardDatabase)
		let makePP = PrinterPoll(printDB:pp)
		let logLevel:Logger.Level
		#if DEBUG
		logLevel = .trace
		#else
		logLevel = .error
		#endif
		let v4 = HBApplication(configuration:.init(address:.hostname("127.0.0.1", port:Int(port)), logLevel:logLevel))
        let v6 = HBApplication(configuration:.init(address:.hostname("::1", port:Int(port)), logLevel:logLevel))
        self.ipv6Application = v6
        self.ipv4Application = v4
        self.wgAPI = wgapi
        self.wgGetKey = wgget
		self.pp = makePP
    }
    
    func run() throws {
        ipv6Application.router.add("wg_makekey", method:.GET, responder:wgAPI)
        ipv4Application.router.add("wg_makekey", method:.GET, responder:wgAPI)
        ipv6Application.router.add("wg_getkey", method:.GET, responder:wgGetKey)
        ipv4Application.router.add("wg_getkey", method:.GET, responder:wgGetKey)
        ipv6Application.router.add("print", method:.POST, responder:pp)
        ipv4Application.router.add("print", method:.POST, responder:pp)
		ipv6Application.router.add("print", method:.GET, responder:pp)
		ipv4Application.router.add("print", method:.GET, responder:pp)
		ipv6Application.router.add("print", method:.DELETE, responder:pp)
		ipv4Application.router.add("print", method:.DELETE, responder:pp)
        try ipv4Application.start()
        try ipv6Application.start()
    }
    
    func wait() {
        ipv6Application.wait()
        ipv4Application.wait()
    }
}

fileprivate struct PrinterPoll:HBResponder {
    struct Response:Encodable {
        let jobReady:Bool
        let mediaTypes = ["plain/text"]
        let jobToken:String?
    }
	
	let printDB:PrintDB
	
	public func respond(to request:HBRequest) -> EventLoopFuture<HBResponse> {
		// check for the remote address
		guard let remoteAddress = request.headers["X-Real-IP"].first?.lowercased() else {
			request.logger.error("no remote address was found in this request")
			return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
		}

		// check which domain the user is requesting from
		guard let domainString = request.headers["Host"].first?.lowercased() else {
			request.logger.error("no domain was found in this request", metadata:["remote":"\(remoteAddress)"])
			return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
		}
		// check for the mac address
		guard let mac = request.headers["X-Star-Mac"].first?.lowercased() else {
			request.logger.error("no mac address was found in this request", metadata:["remote":"\(remoteAddress)"])
			return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
		}
	
		// log the beginning of this traffic
		request.logger.trace("cloudprint traffic identified", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])

        do {
			// check for the user agent
			guard let userAgent = request.headers["User-Agent"].first else {
				request.logger.error("no user agent was found in this request", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
				return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
			}
			// check for the serial number
			guard let serial = request.headers["X-Star-Serial-Number"].first else {
				request.logger.error("no serial number was found in this request", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
				return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
			}
			
			// mark the date
			let date = Date()
			
			// this is the function that will actually return a useful and accurate response to the printer
			let authorization = request.headers["Authorization"].first?.makeAuthData()
			if (authorization != nil) {
				request.logger.debug("decoded authentication username from traffic: '\(authorization!.un)'", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
			}
			
			do {
				switch request.method {
				case .POST:
					// this is a poll that contains useful metadata. parse the request
					guard let requestData = request.body.buffer else {
						request.logger.error("no request body was found", metadata:["remote":"\(remoteAddress)"])
						return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
					}
					guard let parsed = try JSONSerialization.jsonObject(with:requestData) as? [String:Any], let statusCode = parsed["statusCode"] as? String, let decodeStatusCode = statusCode.removingPercentEncoding else {
						request.logger.error("unable to parse json body for this request", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
						return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
					}
					
					let jobCode = try printDB.checkForPrintJobs(mac:mac, ua:userAgent, serial:serial, status:decodeStatusCode, remoteAddress:remoteAddress, date:date, domain:domainString, auth:authorization)
					
					var buildObject:[String:Any] = ["mediaTypes": ["text/plain"]]
					if jobCode != nil {
						let asb64 = jobCode!.base64EncodedString()
						request.logger.notice("printer is polling for new jobs. responding with latest job token: '\(asb64)", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
						buildObject["jobToken"] = asb64
						buildObject["jobReady"] = true
					} else {
						request.logger.notice("printer is polling for new jobs. there are no jobs available.", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
						buildObject["jobReady"] = false
					}
					
					let jsonData = try JSONSerialization.data(withJSONObject:buildObject)
					var responseData = request.context.allocator.buffer(capacity:jsonData.count)
					responseData.writeData(jsonData)
					return request.eventLoop.makeSucceededFuture(HBResponse(status:.ok, headers:HTTPHeaders(dictionaryLiteral:("Content-Type", "application/json")), body:.byteBuffer(responseData)))
				case .GET:
					guard let jobToken = request.uri.queryParameters["token"] else {
						request.logger.error("printer is calling job retrieval endpoint but never provided a job token. this is not expected.", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
						return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
					}
					let (jobData, cutMode) = try printDB.retrievePrintJob(token:Data(base64Encoded:jobToken)! ,mac:mac, ua:userAgent, serial:serial, remoteAddress:remoteAddress, date:date, domain:domainString, auth:authorization)
					var newByteBuffer = request.context.allocator.buffer(capacity:jobData.count)
					newByteBuffer.writeData(jobData)
					request.logger.notice("returning \(newByteBuffer.readableBytes) bytes for job token: '\(jobToken)'", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
					return request.eventLoop.makeSucceededFuture(HBResponse(status:.ok, headers:HTTPHeaders(dictionaryLiteral:("Content-Type", "text/plain"), ("X-Star-Cut", "\(cutMode.rawValue); feed=true")), body:.byteBuffer(newByteBuffer)))
					
				case .DELETE:
					guard let jobToken = request.uri.queryParameters["token"] else {
						request.logger.error("printer is calling job deletion endpoint but never provided a job token. this is not expected.", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
						return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
					}
					try printDB.completePrintJob(token:Data(base64Encoded:jobToken)!, mac:mac, ua:userAgent, serial:serial, remoteAddress:remoteAddress, date:date, domain:domainString, auth:authorization)
					request.logger.notice("job token successfully printed and cleared: '\(jobToken)'", metadata:["remote":"\(remoteAddress)", "mac":"\(mac)"])
					return request.eventLoop.makeSucceededFuture(HBResponse(status:.ok))
				default:
					return request.eventLoop.makeSucceededFuture(HBResponse(status:.notFound))
				}
			} catch PrintDB.AuthorizationError.unauthorized {
				request.logger.error("unauthorized printer poll", metadata:["mac": "\(mac)"])
				return request.eventLoop.makeSucceededFuture(HBResponse(status:.unauthorized))
			} catch let PrintDB.AuthorizationError.reauthorizationRequired(authRealm) {
				request.logger.error("requesting requthentication", metadata:["mac": "\(mac)"])
				return request.eventLoop.makeSucceededFuture(HBResponse(status:.unauthorized, headers:HTTPHeaders([("WWW-Authenticate", "Basic realm=\"\(authRealm)\"")])))
			} catch let PrintDB.AuthorizationError.invalidScope(correctRealm) {
				request.logger.error("printer is polling incorrect subnet", metadata:["mac": "\(mac)", "currentPollSubnet": "\(domainString)", "correctPollSubnet": "\(correctRealm)"])
				return request.eventLoop.makeSucceededFuture(HBResponse(status:.forbidden))
			}
        } catch let error {
            request.logger.error("error thrown - \(error)")
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}

fileprivate struct Wireguard_GetKeyResponder:HBResponder {
    
    let wgDatabase:WireguardDatabase
    
    init(wg_db:WireguardDatabase) {
        wgDatabase = wg_db
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

			// validate that the host name is provided
            guard let publicKey = request.uri.queryParameters["pk"] else {
                request.logger.error("private key not provided")
                return request.eventLoop.makeSucceededFuture(HBResponse(status:.badRequest))
            }
            
            let config = try wgDatabase.getConfiguration(publicKey:publicKey, subnetName:domainString)
            
            var writeBuffer = request.context.allocator.buffer(capacity:config.configuration.count)
            writeBuffer.writeString(config.configuration)
            
			let newResponse = HBResponse(status:.ok, headers:HTTPHeaders([("Content-Disposition", "attachment; filename=\"\(config.name.filter({ ($0.isASCII) && ($0.isLetter || $0.isNumber) })).conf\";")]), body:.byteBuffer(writeBuffer))
            return request.eventLoop.makeSucceededFuture(newResponse)
        } catch let error {
            request.logger.error("error thrown - \(error)")
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
fileprivate struct Wireguard_MakeKeyResponder:HBResponder {
	let daemonDB:DaemonDB
    let wgDatabase:WireguardDatabase
    let wgServerPort:UInt16
    
	init(ddb:DaemonDB) throws {
		self.daemonDB = ddb
		self.wgDatabase = ddb.wireguardDatabase
        self.wgServerPort = try ddb.wireguardDatabase.getPublicListenPort()
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
				let newKeys = try await WireguardExecutor.generateClient()
				
				let (wg_dns_name, wg_port, wg_internal_network, serverV4, pubKey, interfaceName, publicV4) = try wgdb.getWireguardConfigMetas()
				
				let newClientAddress:AddressV6
				let optionalV4:AddressV4?
				let pubKeyRemove:String?
				do {
					(newClientAddress, optionalV4) = try wgdb.clientMake(name:keyName, publicKey:newKeys.publicKey, subnet:domainString, ipv4:false)
					pubKeyRemove = nil
				} catch LMDBError.keyExists {
					request.logger.info("client name already exists on this subnet", metadata:["client": "\(keyName)", "subnet": "\(domainString)"])
					pubKeyRemove = try wgdb.clientRemove(subnet:domainString, name:keyName)
					(newClientAddress, optionalV4) = try wgdb.clientMake(name:keyName, publicKey:newKeys.publicKey, subnet:domainString, ipv4:false)
				}
                
                var buildKey = "[Interface]\n"
                buildKey += "PrivateKey = " + newKeys.privateKey + "\n"
                buildKey += "Address = " + newClientAddress.string + "/128\n"
				if optionalV4 != nil {
					buildKey += "Address = " + optionalV4!.string + "/32\n"
				}
                buildKey += "DNS = " + wg_internal_network.address.string + "\n"
                buildKey += "[Peer]\n"
                buildKey += "PublicKey = " + pubKey + "\n"
                buildKey += "PresharedKey = " + newKeys.presharedKey + "\n"
                buildKey += "AllowedIPs = " + wg_internal_network.cidrString
				if (optionalV4 != nil) {
					buildKey += ", \(serverV4)/32\n"
				} else {
					buildKey += "\n"
				}
				if let publicV4 = publicV4 {
					buildKey += "Endpoint = \(publicV4.string):\(wg_port)\n"
				} else {
					buildKey += "Endpoint = \(wg_dns_name):\(wg_port)\n"
				}
                buildKey += "PersistentKeepalive = 25" + "\n"
                
                var buildBytes = ByteBuffer()
                buildBytes.writeString(buildKey)
                
				if (pubKeyRemove != nil) {
					try await WireguardExecutor.uninstall(publicKey:pubKeyRemove!, interfaceName:interfaceName)
				}
				try await WireguardExecutor.install(publicKey:newKeys.publicKey, presharedKey:newKeys.presharedKey, address:newClientAddress, addressv4:optionalV4, interfaceName:interfaceName)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:self.daemonDB)
				Task.detached {
					try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
					try await DNSmasqExecutor.reload()
				}
                return HBResponse(status: .ok, body:.byteBuffer(buildBytes))
            })
            return keyPromise.futureResult
        } catch let error {
            request.logger.error("error thrown - \(error)")
            return request.eventLoop.makeFailedFuture(error)
        }
    }
}
