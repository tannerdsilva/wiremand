import QuickLMDB
import Foundation
import CLMDB

actor PrintDB {
	enum CutMode:String {
		case full = "full"
		case partial = "partial"
		case none = "none"
	}
    actor Logger {
        struct Event {
            let date:Date
            let mac:String
            let eventMessage:String
            let additionalData:[String:String]
        }
        enum Databases:String {
            case date_uid = "date_uid"               // Date:String
            case uid_eventData = "uid_eventData"     // String:[String:String]
            case uid_mac = "uid_mac"                 // String:String
            case uid_message = "uid_message"         // String:String
        }
		let envPath:URL
		var lastMapResize:Date
		
        let env:Environment
        let date_uid:Database
        let uid_eventData:Database
        let uid_mac:Database
        let uid_message:Database
        
        let syncTask:Task<Void, Swift.Error>
        
        init(directory:URL) throws {
			let envPath = directory.appendingPathComponent("printerlogs-dbi")
			let getSize:size_t = size_t((envPath.getFileSize() ?? 10000000000) + 5000000000)
			let makeEnv = try Environment(path:envPath.path, flags:[.noSubDir, .noSync], mapSize: getSize)
            let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
                let date_uid:Database = try makeEnv.openDatabase(named:Databases.date_uid.rawValue, flags:[.create], tx:someTrans)
                let uid_eventData = try makeEnv.openDatabase(named:Databases.uid_eventData.rawValue, flags:[.create], tx:someTrans)
                let uid_mac = try makeEnv.openDatabase(named:Databases.uid_mac.rawValue, flags:[.create], tx:someTrans)
                let uid_message = try makeEnv.openDatabase(named:Databases.uid_message.rawValue, flags:[.create], tx:someTrans)
                return [date_uid, uid_eventData, uid_mac, uid_message]
            }
			self.envPath = envPath
            self.env = makeEnv
            self.date_uid = dbs[0]
            self.uid_eventData = dbs[1]
            self.uid_mac = dbs[2]
            self.uid_message = dbs[3]
            self.syncTask = Task.detached(operation: { [getEnv = makeEnv] in
                while Task.isCancelled == false {
                    try await Task.sleep(nanoseconds:1000000000 * 5)
                    try getEnv.sync(force:true)
                }
            })
			self.lastMapResize = Date()
        }
		
        func document(event:Event) throws {
			if lastMapResize.timeIntervalSinceNow < -86400 {
				let getSize:size_t = size_t((envPath.getFileSize() ?? 10000000000) + 5000000000)
				try env.setMapSize(getSize)
				lastMapResize = Date()
			}
			try env.transact(readOnly:false) { someTrans in
				// generate a unique id
				var newUID = UUID().uuidString
				while try uid_eventData.containsEntry(key:newUID, tx:someTrans) == true {
					newUID = UUID().uuidString
				}
				
				// write it
				try date_uid.setEntry(value:newUID, forKey:event.date, flags:[.noOverwrite], tx:someTrans)
				try uid_eventData.setEntry(value:event.additionalData, forKey:newUID, flags:[.noOverwrite], tx:someTrans)
				try uid_mac.setEntry(value:event.mac, forKey:newUID, flags:[.noOverwrite], tx:someTrans)
				try uid_message.setEntry(value:event.eventMessage, forKey:newUID, flags:[.noOverwrite], tx:someTrans)
			}
        }
        
        nonisolated func getEvents(until pastDate:Date, mac:String? = nil) throws -> [Event] {
            try env.transact(readOnly:true) { someTrans in
                let timelineCursor = try date_uid.cursor(tx:someTrans)
                let eventDataCursor = try uid_eventData.cursor(tx:someTrans)
                let macCursor = try uid_mac.cursor(tx:someTrans)
                let messageCursor = try uid_message.cursor(tx:someTrans)
                var buildEvents = [Event]()
                do {
                    var operation = Cursor.Operation.last
                    var getDate:Date
                    repeat {
                        let item = try timelineCursor.getEntry(operation)
                        getDate = Date(item.key)!
                        switch operation {
                        case .last:
                            operation = .previous
                        default:
                            break;
                        }
                        let macVal = String(try macCursor.getEntry(.set, key:item.value).value)!
                        let eventDataVal = Dictionary<String, String>(try eventDataCursor.getEntry(.set, key:item.value).value)!
                        let eventMessageVal = String(try messageCursor.getEntry(.set, key:item.value).value)!
                        if (mac == nil || mac! == macVal) {
                            buildEvents.append(Event(date:getDate, mac:macVal, eventMessage:eventMessageVal, additionalData:eventDataVal))
                        }
                    } while getDate > pastDate
                    
                } catch LMDBError.notFound {}
                return buildEvents
            }
        }
    }

	enum Metadatas:String {
        case startPort = "initPort"     //UInt16
        case endPort = "endPort"        //UInt16
    }
    enum Databases:String {
        case metadata = "_metadata"
        
        // databases for authorized (configured) printers
        // - printers that are unconfigured or otherwise "revoked" from the system will not have data in these databases
        case tcpPortNumber_mac = "tcpport_mac"			//UInt16:String
        case mac_tcpPortNumber = "mac_tcpport"			//String:UInt16
        case mac_un = "mac_un"							//String:String
		case mac_pw = "mac_pw"							//String:String
        case mac_subnetName = "mac_subnetName"			//String:String
        case mac_cutMode = "mac_cutMode"				//String:CutMode
		
        // print jobs for authorized printers
        case mac_printJobDate = "mac_printJobDate"                              //String:Date [DUPSORT]
        case macPrintJobHash_printJobData = "macPrintJobHash_printJobData"      //Data:Data
        
		// data that only gets updated when a valid authentication proof is presented
		case mac_lastAuthenticated = "mac_lastAuthenticated"    //String:Date
		case mac_remoteAddress = "mac_remoteAddress"            //String:String
		case mac_serial = "mac_serial"                          //String:String

		// authentication not required for these to get updated
        case mac_lastSeen = "mac_lastSeen"                      //Stirng:Date
        case mac_status = "mac_status"                          //String:String
        case mac_userAgent = "mac_userAgent"                    //String:String
		case mac_callingDomain = "mac_callingDomain"			//String:String
		case mac_lastUN = "mac_lastUN"							//String:String
		case mac_lastPW = "mac_lastPW"							//String:String
		case mac_lastAuthAttempt = "mac_lastAuthAttempt"		//String:Date
    }
    
    let env:Environment
    
    let metadata:Database
    
	// for authorized printers
	struct AuthorizedPrinter {
		let mac:String
		let port:UInt16
		let username:String
		let password:String
		let subnet:String
		let cutMode:CutMode
	}
    let port_mac:Database
    let mac_port:Database
	let mac_un:Database
	let mac_pw:Database
    let mac_subnetName:Database
	let mac_cutMode:Database
	
	nonisolated func _addAuthorizedPrinter(mac:String, subnet:String, tx:Transaction) throws -> (port:UInt16, username:String, password:String) {
		let pw = String.random(length:12, separator:"_")
		let un = String.random(length:12, separator:"_")
		let newPort = try tx.transact(readOnly:false) { [pw, un] someTrans -> UInt16 in
			var newPort:UInt16
			let getFirstPort = try metadata.getEntry(type:UInt16.self, forKey:Metadatas.startPort.rawValue, tx:someTrans)!
			let getLastPort = try metadata.getEntry(type:UInt16.self, forKey:Metadatas.endPort.rawValue, tx:someTrans)!
			repeat {
				newPort = UInt16.random(in:getFirstPort...getLastPort)
			} while try self.port_mac.containsEntry(key:newPort, tx:someTrans) == true
			
			try port_mac.setEntry(value:mac, forKey:newPort, flags:[.noOverwrite], tx:someTrans)
			try mac_port.setEntry(value:newPort, forKey:mac, flags:[.noOverwrite], tx:someTrans)
			try mac_un.setEntry(value:un, forKey:mac, flags:[.noOverwrite], tx:someTrans)
			try mac_pw.setEntry(value:pw, forKey:mac, flags:[.noOverwrite], tx:someTrans)
			try mac_subnetName.setEntry(value:subnet, forKey:mac, flags:[.noOverwrite], tx:someTrans)
			try mac_cutMode.setEntry(value:CutMode.full.rawValue, forKey:mac, flags:[.noOverwrite], tx:someTrans)
			return newPort
		}
		Task.detached {
			try await self.firePortOpener(port:newPort, mac:mac)
		}
		return (newPort, un, pw)
	}
	
	nonisolated func authorizeMacAddress(mac:String, subnet:String) throws -> (port:UInt16, username:String, password:String) {
		defer {
			try? env.sync()
		}
		return try env.transact(readOnly:false) { someTrans in
			return try _addAuthorizedPrinter(mac:mac, subnet:subnet, tx:someTrans)
		}
	}
	
	nonisolated func assignCutMode(mac:String, mode:CutMode) throws {
		try env.transact(readOnly:false) { someTrans in
			return try mac_cutMode.setEntry(value:mode.rawValue, forKey:mac, tx:someTrans)
		}
	}
	
	nonisolated func deauthorizeMacAddress(mac:String) throws {
		let closedPort = try env.transact(readOnly:false) { someTrans -> UInt16 in
			//get the port for this mac
			let getPort = try self.mac_port.getEntry(type:UInt16.self, forKey:mac, tx:someTrans)!
			try self.port_mac.deleteEntry(key:getPort, tx:someTrans)
			try self.mac_port.deleteEntry(key:mac, tx:someTrans)
			try self.mac_un.deleteEntry(key:mac, tx:someTrans)
			try self.mac_pw.deleteEntry(key:mac, tx:someTrans)
			try self.mac_subnetName.deleteEntry(key:mac, tx:someTrans)
			try self.mac_cutMode.deleteEntry(key:mac, tx:someTrans)
			return getPort
		}
		Task.detached {
			try await self.firePortCloser(port:closedPort)
		}
	}
	
	nonisolated func getAuthorizedPrinterInfo() throws -> [AuthorizedPrinter] {
		return try env.transact(readOnly:true) { someTrans in
			let port_macCursor = try port_mac.cursor(tx:someTrans)
			var buildList = [AuthorizedPrinter]()
			for curMacPort in port_macCursor {
				let macAddress = String(curMacPort.value)!
				let portNumber = UInt16(curMacPort.key)!
				let un = try mac_un.getEntry(type:String.self, forKey:macAddress, tx:someTrans)!
				let pw = try mac_pw.getEntry(type:String.self, forKey:macAddress, tx:someTrans)!
				let subnet = try mac_subnetName.getEntry(type:String.self, forKey:macAddress, tx:someTrans)!
				let cutMode = CutMode(rawValue:try mac_cutMode.getEntry(type:String.self, forKey:macAddress, tx:someTrans)!)!
				buildList.append(AuthorizedPrinter(mac:macAddress, port:portNumber, username:un, password:pw, subnet:subnet, cutMode:cutMode))
			}
			return buildList
		}
	}
	
	// jobs for authorized printers
    let mac_printJobDate:Database
    let macPrintHash_printJobData:Database
    
    let mac_lastAuthenticated:Database
	let mac_remoteAddress:Database
	let mac_serial:Database
	
    let mac_lastSeen:Database
    let mac_status:Database
    let mac_userAgent:Database
	let mac_callingDomain:Database
	let mac_lastUN:Database
	let mac_lastPW:Database
	let mac_lastAuthAttempt:Database
	
	typealias OpenHandler = (UInt16, String) throws -> Void
	typealias CloseHandler = (UInt16) throws -> Void
	fileprivate var opener:OpenHandler? = nil
	fileprivate var closer:CloseHandler? = nil
	fileprivate var openedPort = Set<UInt16>()
	func assignPortHandlers(opener:@escaping(OpenHandler), closer:@escaping(CloseHandler)) throws {
		guard self.opener == nil && self.closer == nil else {
			return
		}
		self.opener = opener
		self.closer = closer
		try env.transact(readOnly:true) { someTrans in
			let port_macCursor = try port_mac.cursor(tx:someTrans)
			for curPort in port_macCursor {
				let asUInt = UInt16(curPort.key)!
				let macStr = String(curPort.value)!
				try opener(asUInt, macStr)
				openedPort.update(with:asUInt)
			}
		}
	}
	func portSync() throws {
		guard opener != nil && closer != nil else {
			return
		}
		try env.transact(readOnly:true) { someTrans in
			let port_macCursor = try port_mac.cursor(tx:someTrans)
			
			// open any unopened ports
			for curPort in port_macCursor {
				let asUInt = UInt16(curPort.key)!
				let macStr = String(curPort.value)!
				if openedPort.contains(asUInt) {
					try opener!(asUInt, macStr)
					openedPort.update(with:asUInt)
				}
			}
			// close any opened ports which should not be running
			for curPort in openedPort {
				if try port_macCursor.containsEntry(key:curPort) == false {
					try closer!(curPort)
					openedPort.remove(curPort)
				}
			}
		}
	}
	fileprivate func firePortOpener(port:UInt16, mac:String) throws {
		if let hasOpener = opener, openedPort.contains(port) == false {
			try hasOpener(port, mac)
			openedPort.update(with:port)
		}
	}
	fileprivate func firePortCloser(port:UInt16) throws {
		if let hasCloser = closer, openedPort.contains(port) == true {
			try hasCloser(port)
			openedPort.remove(port)
		}
	}

    let logger:Logger
	
	struct AuthData {
		let un:String
		let pw:String
	}
	init(environment:Environment, directory:URL) throws {
        let makeEnv = environment
        let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
            let meta = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[.create], tx:someTrans)
            let p_m = try makeEnv.openDatabase(named:Databases.tcpPortNumber_mac.rawValue, flags:[.create], tx:someTrans)
            let m_p = try makeEnv.openDatabase(named:Databases.mac_tcpPortNumber.rawValue, flags:[.create], tx:someTrans)
            let mac_un = try makeEnv.openDatabase(named:Databases.mac_un.rawValue, flags:[.create], tx:someTrans)
			let mac_pw = try makeEnv.openDatabase(named:Databases.mac_pw.rawValue, flags:[.create], tx:someTrans)
			let mac_sub = try makeEnv.openDatabase(named:Databases.mac_subnetName.rawValue, flags:[.create], tx:someTrans)
			let mac_cutMode:Database
			do {
				mac_cutMode = try makeEnv.openDatabase(named:Databases.mac_cutMode.rawValue, flags:[], tx:someTrans)
			} catch LMDBError.notFound {
				mac_cutMode = try makeEnv.openDatabase(named:Databases.mac_cutMode.rawValue, flags:[.create], tx:someTrans)
				let macCursor = try mac_sub.cursor(tx:someTrans)
				for curMac in macCursor {
					try mac_cutMode.setEntry(value:CutMode.full.rawValue, forKey:String(curMac.key)!, tx:someTrans)
				}
			}
			
            let mac_printDate = try makeEnv.openDatabase(named:Databases.mac_printJobDate.rawValue, flags:[.create, .dupSort], tx:someTrans)
            let macPrintHash_jobData = try makeEnv.openDatabase(named:Databases.macPrintJobHash_printJobData.rawValue, flags:[.create], tx:someTrans)
            
            let mac_authDate = try makeEnv.openDatabase(named:Databases.mac_lastAuthenticated.rawValue, flags:[.create], tx:someTrans)
			let mac_remoteAddress = try makeEnv.openDatabase(named:Databases.mac_remoteAddress.rawValue, flags:[.create], tx:someTrans)
			let mac_serial = try makeEnv.openDatabase(named:Databases.mac_serial.rawValue, flags:[.create], tx:someTrans)

            let mac_lastSeen = try makeEnv.openDatabase(named:Databases.mac_lastSeen.rawValue, flags:[.create], tx:someTrans)
            let mac_status = try makeEnv.openDatabase(named:Databases.mac_status.rawValue, flags:[.create], tx:someTrans)
            let mac_ua = try makeEnv.openDatabase(named:Databases.mac_userAgent.rawValue, flags:[.create], tx:someTrans)
			let mac_cd = try makeEnv.openDatabase(named:Databases.mac_callingDomain.rawValue, flags:[.create], tx:someTrans)
			let mac_lastUN = try makeEnv.openDatabase(named:Databases.mac_lastUN.rawValue, flags:[.create], tx:someTrans)
			let mac_lastPW = try makeEnv.openDatabase(named:Databases.mac_lastPW.rawValue, flags:[.create], tx:someTrans)
			let mac_lastAuthAtt = try makeEnv.openDatabase(named:Databases.mac_lastAuthAttempt.rawValue, flags:[.create], tx:someTrans)
			
			// assign initial values
			do {
				_ = try meta.getEntry(type:UInt16.self, forKey:Metadatas.startPort.rawValue, tx:someTrans)
				_ = try meta.getEntry(type:UInt16.self, forKey:Metadatas.endPort.rawValue, tx:someTrans)
			} catch LMDBError.notFound {
				do {
					_ = try meta.setEntry(value:UInt16(9100), forKey:Metadatas.startPort.rawValue, flags:[.noOverwrite], tx:someTrans)
					_ = try meta.setEntry(value:UInt16(9300), forKey:Metadatas.endPort.rawValue, flags:[.noOverwrite], tx:someTrans)
				} catch LMDBError.keyExists {}
			}
			
			return [meta, p_m, m_p, mac_un, mac_pw, mac_sub, mac_cutMode, mac_printDate, macPrintHash_jobData, mac_authDate, mac_remoteAddress, mac_serial, mac_lastSeen, mac_status, mac_ua, mac_cd, mac_lastUN, mac_lastPW, mac_lastAuthAtt]
        }
		try makeEnv.sync(force:true)
		self.env = makeEnv
        self.metadata = dbs[0]
        self.port_mac = dbs[1]
        self.mac_port = dbs[2]
		self.mac_un = dbs[3]
		self.mac_pw = dbs[4]
        self.mac_subnetName = dbs[5]
		self.mac_cutMode = dbs[6]
	
        self.mac_printJobDate = dbs[7]
        self.macPrintHash_printJobData = dbs[8]
		
        self.mac_lastAuthenticated = dbs[9]
        self.mac_remoteAddress = dbs[10]
        self.mac_serial = dbs[11]
		
		self.mac_lastSeen = dbs[12]
		self.mac_status = dbs[13]
		self.mac_userAgent = dbs[14]
		self.mac_callingDomain = dbs[15]
		self.mac_lastUN = dbs[16]
		self.mac_lastPW = dbs[17]
		self.mac_lastAuthAttempt = dbs[18]
		
		self.logger = try Logger(directory:directory)
    }
	
	// returns the oldest job token for a given mac address
	nonisolated fileprivate func _oldestJobHash(mac:String, tx:Transaction) throws -> Data {
		let macPrintCursor = try mac_printJobDate.cursor(tx:tx)
		_ = try macPrintCursor.getEntry(.set, key:mac)
		// there are print jobs, now get the oldest job and return it as a job hash
		let combinedData = Data(mac.utf8) + Data(try macPrintCursor.getEntry(.firstDup).value)!
		return try Blake2bHasher.hash(data:combinedData, length:16)
	}
	
	// installs a new print job for a specified mac address
	nonisolated fileprivate func _newJob(mac:String, date:Date, data:Data, tx:Transaction) throws {
		// open cursors
		let macPrintCursor = try mac_printJobDate.cursor(tx:tx)
		let macPrintJobDataCursor = try macPrintHash_printJobData.cursor(tx:tx)
		
		try date.asMDB_val({ dateVal in
			try macPrintCursor.setEntry(value:dateVal, forKey:mac, flags:[.noDupData])	
			let combinedData = Data(mac.utf8) + Data(dateVal)!
			let jobHash = try Blake2bHasher.hash(data:combinedData, length:16)
			try macPrintJobDataCursor.setEntry(value:data, forKey:jobHash)
		})
	}
	
	nonisolated fileprivate func _deleteJob(hash:Data, tx:Transaction) throws {
		let macPrintCursor = try mac_printJobDate.cursor(tx:tx)
		try macPrintHash_printJobData.deleteEntry(key:hash, tx:tx)
		for curKV in macPrintCursor {
			let combinedData = Data(curKV.key)! + Data(curKV.value)!
			let thisHashData = try Blake2bHasher.hash(data:combinedData, length:16)
			if (thisHashData == hash) {
				try macPrintCursor.deleteEntry()
				return
			}
		}
		throw LMDBError.notFound
	}

	nonisolated func _documentSighting(mac:String, ua:String, serial:String, status:String?, remoteAddress:String, date:Date, domain:String, auth:AuthData?, tx:Transaction) throws {
		try mac_lastSeen.setEntry(value:date, forKey:mac, tx:tx)
		if status != nil {
			try mac_status.setEntry(value:status!, forKey:mac, tx:tx)
		}
		try mac_userAgent.setEntry(value:ua, forKey:mac, tx:tx)
		try mac_callingDomain.setEntry(value:domain, forKey:mac, tx:tx)
		if (auth != nil) {
			try mac_lastUN.setEntry(value:auth!.un, forKey:mac, tx:tx)
			try mac_lastPW.setEntry(value:auth!.pw, forKey:mac, tx:tx)
			try mac_lastAuthAttempt.setEntry(value:date, forKey:mac, tx:tx)
		}
	}
	enum AuthorizationError:Error {
		case unauthorized
		case invalidScope(String)
		case reauthorizationRequired(String)
	}
	nonisolated func _authenticationCheck(mac:String, serial:String, remoteAddress:String, date:Date, domain:String, auth:AuthData? = nil, tx:Transaction) throws {
		try tx.transact(readOnly:false) { authCheckTrans in
			// validate that this printer is registered (by retrieving its subnet)
			let subnetName:String
			do {
				subnetName = try self.mac_subnetName.getEntry(type:String.self, forKey:mac, tx:authCheckTrans)!
			} catch LMDBError.notFound {
				throw AuthorizationError.unauthorized
			}
			
			// must be authorized on the domain it is calling into
			guard domain == subnetName else {
				throw AuthorizationError.invalidScope(subnetName)
			}
			
			// now we need to actually determine if this printer will be authorized. this happens based on the value of the authorization value
			if (auth == nil) {
				// get the last authorization date
				let lastAuthorized:Date
				do {
					lastAuthorized = try mac_lastAuthenticated.getEntry(type:Date.self, forKey:mac, tx:authCheckTrans)!
					guard lastAuthorized.timeIntervalSinceNow > -86400 else {
						throw AuthorizationError.reauthorizationRequired(subnetName)
					}
				} catch LMDBError.notFound {
					throw AuthorizationError.reauthorizationRequired(subnetName)
				}
				
				// if the printer has pending jobs - the authorization requirements will shift into a more frequent interval
				if try mac_printJobDate.containsEntry(key:mac, tx:authCheckTrans) {
					// there are print jobs - user must reauthenticate if they haven't within the last hour
					guard lastAuthorized.timeIntervalSinceNow > -3600 else {
						throw AuthorizationError.reauthorizationRequired(subnetName)
					}
				}
				
				// authorization data will need to be trusted from the previous metadata
				do {
					let checkSerial = try self.mac_serial.getEntry(type:String.self, forKey:mac, tx:authCheckTrans)!
					let checkRemote = try self.mac_remoteAddress.getEntry(type:String.self, forKey:mac, tx:authCheckTrans)!
					guard checkRemote == remoteAddress && checkSerial == serial else {
						throw AuthorizationError.reauthorizationRequired(subnetName)
					}
				} catch LMDBError.notFound {
					throw AuthorizationError.reauthorizationRequired(subnetName)
				}
			} else {
				let checkUn = try self.mac_un.getEntry(type:String.self, forKey:mac, tx:authCheckTrans)!
				let checkPw = try self.mac_pw.getEntry(type:String.self, forKey:mac, tx:authCheckTrans)!
				guard auth!.un == checkUn && auth!.pw == checkPw else {
					throw AuthorizationError.unauthorized
				}
				// authorization event just occurred. document the date and refresh the databases that are evaluated for auth caching
				try self.mac_lastAuthenticated.setEntry(value:date, forKey:mac, tx:authCheckTrans)
				try self.mac_serial.setEntry(value:serial, forKey:mac, tx:authCheckTrans)
				try self.mac_remoteAddress.setEntry(value:remoteAddress, forKey:mac, tx:authCheckTrans)
			}
		}
	}
	
	// installs a new print job into the database
	nonisolated func newPrintJob(port:UInt16, date:Date, data:Data) throws {
		try env.transact(readOnly:false) { someTrans in
			let macAddress = try port_mac.getEntry(type:String.self, forKey:port, tx:someTrans)!
			try _newJob(mac:macAddress, date:date, data:data, tx:someTrans)
		}
		try env.sync(force:true)
	}
	
	// check the authentication status of a given printer. if the printer is authorized and it has a print job, this function will return the job token that needs to be printed
	nonisolated func checkForPrintJobs(mac:String, ua:String, serial:String, status:String, remoteAddress:String, date:Date, domain:String, auth:AuthData? = nil) throws -> Data? {
		try env.transact(readOnly:false) { someTrans -> Data? in
			try _documentSighting(mac:mac, ua:ua, serial:serial, status:status, remoteAddress:remoteAddress, date:date, domain:domain, auth:auth, tx:someTrans)
			do {
				try _authenticationCheck(mac:mac, serial:serial, remoteAddress:remoteAddress, date:date, domain:domain, auth:auth, tx:someTrans)
			} catch let error where error is AuthorizationError {
				try someTrans.commit()
				throw error
			}
			do {
				return try _oldestJobHash(mac:mac, tx:someTrans)
			} catch LMDBError.notFound {
				return nil
			}
		}
	}
	
	// check the authentication status of a given printer. assuming that the printer is authenticated, this function will return the raw print data that needs to go to the printer
	nonisolated func retrievePrintJob(token:Data, mac:String, ua:String, serial:String, remoteAddress:String, date:Date, domain:String, auth:AuthData? = nil) throws -> (Data, CutMode) {
		try env.transact(readOnly:false) { someTrans -> (Data, CutMode) in
			try _documentSighting(mac:mac, ua:ua, serial:serial, status:nil, remoteAddress:remoteAddress, date:date, domain:domain, auth:auth, tx:someTrans)
			do {
				try _authenticationCheck(mac:mac, serial:serial, remoteAddress:remoteAddress, date:date, domain:domain, auth:auth, tx:someTrans)
			} catch let error where error is AuthorizationError {
				try someTrans.commit()
				throw error
			}
			let cutMode = CutMode(rawValue:try self.mac_cutMode.getEntry(type:String.self, forKey:mac, tx:someTrans)!)!
			return (try self.macPrintHash_printJobData.getEntry(type:Data.self, forKey:token, tx:someTrans)!, cutMode)
		}
	}
	
	// marks a print job as complete
	nonisolated func completePrintJob(token:Data, mac:String, ua:String, serial:String, remoteAddress:String, date:Date, domain:String, auth:AuthData? = nil) throws {
		try env.transact(readOnly:false) { someTrans in
			try _documentSighting(mac:mac, ua:ua, serial:serial, status:nil, remoteAddress:remoteAddress, date:date, domain:domain, auth:auth, tx:someTrans)
			do {
				try _authenticationCheck(mac:mac, serial:serial, remoteAddress:remoteAddress, date:date, domain:domain, auth:auth, tx:someTrans)
			} catch let error where error is AuthorizationError {
				try someTrans.commit()
				throw error
			}
			try _deleteJob(hash:token, tx:someTrans)
		}
		try env.sync(force:true)
	}
}
