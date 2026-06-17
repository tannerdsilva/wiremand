import QuickLMDB
import Foundation
import Logging
import AsyncHTTPClient
import NIO
import SystemPackage
import RAW
import RAW_blake2
import bedrock

extension bedrock.Date.Seconds: @retroactive MDB_comparable {
	public static var MDB_compare_f: MDB_compare_ftype {
		return { lhs, rhs in
		   guard let lhs = lhs, let rhs = rhs else {
			   return 0
		   }
		   let lsize = lhs.pointee.mv_size
		   let rsize = rhs.pointee.mv_size

		   let lptr = lhs.pointee.mv_data!
		   let rptr = rhs.pointee.mv_data!

		   let minSize = min(lsize, rsize)

		   let cmp = memcmp(lptr, rptr, minSize)
		   if cmp != 0 {
			   return Int32(cmp)
		   }
		   if lsize < rsize { return -1 }
		   if lsize > rsize { return 1 }
		   return 0
	   }
	}
}

@RAW_staticbuff(bytes:8)
@MDB_comparable
public struct IPHash:Sendable, Comparable {
	public init(ipString:EncodedString) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(ipString)
		self = try hasher.finish()
	}
	public init(addressV4:AddressV4) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(addressV4)
		self = try hasher.finish()
	}
	public init(addressV6:AddressV6) throws {
		var hasher = try RAW_blake2.Hasher<B, Self>()
		try hasher.update(addressV6)
		self = try hasher.finish()
	}
}

/// Manages geolocation and ISP metadata resolution for client endpoint IPs using ipstack.com.
/// Architecture:
/// 1. Pending Queue: IPs awaiting resolution, indexed by insertion date.
/// 2. Resolved Cache: Successful lookups with reverse date indexing for stale record rotation.
/// 3. Failed Queue: Exponential backoff via monthly requeue of failed resolutions.
/// - Rotation: Resolved records >60 days old have a 20% chance of re-resolution. Failed records >30 days are retried.
public final class IPDatabase: Sendable {
	public enum ResolveStatus {
		case resolving
		case resolved(ResolvedIPInfo)
		case failedResolving(String)
	}
	
	fileprivate static func makeLogger() -> Logger {
		var newLogger = Logger(label:"ipdb")
		#if DEBUG
			newLogger.logLevel = .trace
		#else
			newLogger.logLevel = .critical
		#endif
		return newLogger
	}
	let log:Logger
	
	enum Databases:String {
		case metadata = "metadata"
		
		// pending IP addresses that need resolving (and the corresponding date in which they were added to the database)
		case date_pendingIP = "date_pendingIP"
		case pendingIP_date = "pendingIP_date"
		
		// for IP addresses that are successfully resolved
		case ipHash_resolvedData = "ipHash_resolvedData"
		case ipHash_resolveSuccessDate = "ipHash_resolveSuccessDate"
		case resolveSuccessDate_ipHash = "resolveSuccessDate_ipHash"
		
		// for failed IP addresses
		case resolveFailDate_ipHash = "resolveFailDate_ipHash"
		case ipHash_resolveFailDate = "ipHash_resolveFailDate"
		case ipHash_resolveFailMessage = "ipHash_resolveFailMessage"
		
		// for both sucessful and failed IP addresses
		case ipHash_ipString = "ipHash_ipString"
	}
	
	enum Metadatas:String {
		case ipstackAccessKey = "ipstack_accessKey"
	}
	
	let env:Environment
	
	// metadata
	let metadata:Database
	
	// for ip addresses that need to be resolved
	let date_pendingIP:Database.Strict<bedrock.Date.Seconds, EncodedString>
	let pendingIP_date:Database.Strict<EncodedString, bedrock.Date.Seconds>
	
	// for successfully resolved data
	let ipHash_resolvedData:Database.Strict<IPHash, ResolvedIPInfo>
	let ipHash_resolveSuccessDate:Database.Strict<IPHash, bedrock.Date.Seconds>
	let resolveSuccessDate_ipHash:Database.Strict<bedrock.Date.Seconds, IPHash>
	
	// for unsuccessfully resolved data
	let resolveFailDate_ipHash:Database.Strict<bedrock.Date.Seconds, IPHash>
	let ipHash_resolveFailDate:Database.Strict<IPHash, bedrock.Date.Seconds>
	let ipHash_resolveFailMessage:Database.Strict<IPHash, EncodedString>
	
	// for both success and failures
	let ipHash_ipString:Database.Strict<IPHash, EncodedString>
	
	public init(base:Path, logLevel:Logger.Level, apiKey:String? = nil) throws {
		var makeLogger = Logger(label:"\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		makeLogger[metadataKey:"env_path"] = "\(base.path())"
		log = makeLogger
		let envPath = base.appendingPathComponent("ipdb_clientinfo")
		let fileSize = envPath.getFileSize() + (16 * 1024 * 1024 * 1024) // current + 16GB
		env = try Environment(path:envPath.path(), flags:[.noSubDir], mapSize:Int(fileSize), maxReaders:32, maxDBs:32, mode:[.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])
		log.debug("successfully created environment", metadata:["mmap_size":"\(fileSize)b"])
		let someTrans = try Transaction(env:env, readOnly:false)
		log.trace("successfully created transaction")
		metadata = try Database(env:env, name:Databases.metadata.rawValue, flags:[.create], tx:someTrans)
		date_pendingIP = try Database.Strict<bedrock.Date.Seconds, EncodedString>(env:env, name:Databases.date_pendingIP.rawValue, flags:[.create], tx:someTrans)
		pendingIP_date = try Database.Strict<EncodedString, bedrock.Date.Seconds>(env:env, name:Databases.pendingIP_date.rawValue, flags:[.create], tx:someTrans)
		ipHash_resolvedData = try Database.Strict<IPHash, ResolvedIPInfo>(env:env, name:Databases.ipHash_resolvedData.rawValue, flags:[.create], tx:someTrans)
		ipHash_resolveSuccessDate = try Database.Strict<IPHash, bedrock.Date.Seconds>(env:env, name:Databases.ipHash_resolveSuccessDate.rawValue, flags:[.create], tx:someTrans)
		resolveSuccessDate_ipHash = try Database.Strict<bedrock.Date.Seconds, IPHash>(env:env, name:Databases.resolveSuccessDate_ipHash.rawValue, flags:[.create], tx:someTrans)
		resolveFailDate_ipHash = try Database.Strict<bedrock.Date.Seconds, IPHash>(env:env, name:Databases.resolveFailDate_ipHash.rawValue, flags:[.create], tx:someTrans)
		ipHash_resolveFailDate = try Database.Strict<IPHash, bedrock.Date.Seconds>(env:env, name:Databases.ipHash_resolveFailDate.rawValue, flags:[.create], tx:someTrans)
		ipHash_resolveFailMessage = try Database.Strict<IPHash, EncodedString>(env:env, name:Databases.ipHash_resolveFailMessage.rawValue, flags:[.create], tx:someTrans)
		ipHash_ipString = try Database.Strict<IPHash, EncodedString>(env:env, name:Databases.ipHash_ipString.rawValue, flags:[.create], tx:someTrans)
		if apiKey != nil {
			try self.metadata.setEntry(key: EncodedString(Metadatas.ipstackAccessKey.rawValue), value: EncodedString(apiKey!), flags: [], tx: someTrans)
		}
		log.trace("successfully created databases")
		try someTrans.commit()
		log.info("successfully initialized IPDatabase")
	}

	static public func deleteDB(base: Path) {
		let envPath = base.appendingPathComponent("ipdb_clientinfo")
		try? FileManager.default.removeItem(at:URL(filePath: envPath.path()))
	}
	
	// installs a pending address. does not mark the current pid as a resolver of this address
	fileprivate func installPending(ipv4:AddressV4, tx:borrowing Transaction) throws {
		let makeDate = bedrock.Date.Seconds()
		try self.date_pendingIP.setEntry(key: makeDate, value: EncodedString(ipv4.string), flags: [.noOverwrite], tx: tx)
		try self.pendingIP_date.setEntry(key: EncodedString(ipv4.string), value: makeDate, flags: [.noOverwrite], tx: tx)
		log.debug("pending IPv4 installed", metadata:["address": "\(ipv4.string)"])
	}
	
	// installs a pending address. does not mark the current pid as a resolver for this address
	fileprivate func installPending(ipv6:AddressV6, tx:borrowing Transaction) throws {
		let makeDate = bedrock.Date.Seconds()
		try self.date_pendingIP.setEntry(key: makeDate, value: EncodedString(ipv6.string), flags: [.noOverwrite], tx: tx)
		try self.pendingIP_date.setEntry(key: EncodedString(ipv6.string), value: makeDate, flags: [.noOverwrite], tx: tx)
		log.debug("pending IPv6 installed", metadata:["address": "\(ipv6.string)"])
	}
	
	// PRIVATE USE ONLY (for retrying failed addresses) installs a pending address. does not mark the current pid as a resolver of this address
	fileprivate func installPending(address:EncodedString, tx:borrowing Transaction) throws {
		let makeDate = bedrock.Date.Seconds()
		try self.date_pendingIP.setEntry(key: makeDate, value: address, flags: [.noOverwrite], tx: tx)
		try self.pendingIP_date.setEntry(key: address, value: makeDate, flags: [.noOverwrite], tx: tx)
		log.debug("pending IP (string) installed", metadata:["address": "\(String(address))"])
	}
	
	// installs a resolved address string into the database with the corresponding IP information.
	// may overwrite data if it already exists in the database
	fileprivate func installSuccessfulResolve(address:EncodedString, resolution:ResolvedIPInfo, tx:borrowing Transaction) throws {
		let successDate = bedrock.Date.Seconds()
		let ipHash = try IPHash(ipString: address)
		do {
			let ipHashSuccessDate = try self.ipHash_resolveSuccessDate.loadEntry(key: ipHash, tx: tx)
			try self.resolveSuccessDate_ipHash.deleteEntry(key: ipHashSuccessDate, tx: tx)
			try self.ipHash_resolveSuccessDate.deleteEntry(key: ipHash, tx: tx)
		} catch LMDBError.notFound {}
		
		try self.ipHash_resolvedData.setEntry(key: ipHash, value: resolution, flags: [.noOverwrite], tx: tx)
		try self.ipHash_resolveSuccessDate.setEntry(key: ipHash, value: successDate, flags: [.noOverwrite], tx: tx)
		try self.resolveSuccessDate_ipHash.setEntry(key: successDate, value: ipHash, flags: [.noOverwrite], tx: tx)
		try self.ipHash_ipString.setEntry(key: ipHash, value: address, flags: [.noOverwrite], tx: tx)
		log.debug("installed resolution info", metadata:["address": "\(address)"])
	}
	
	fileprivate func uninstallPending(addressString:EncodedString, tx:borrowing Transaction) throws {
		let date = try self.pendingIP_date.cursor(tx:tx) { cursor in
			let date = try cursor.opSet(key:addressString)
			try self.date_pendingIP.deleteEntry(key:date, tx:tx)
			try cursor.deleteCurrentEntry(flags: [])
			return date
		}
		log.debug("pending IP uninstalled", metadata:["db_address": "\(String(addressString))", "db_date": "\(date.iso8601String())"])
	}

	public func uninstallPending(addressString:EncodedString) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try uninstallPending(addressString: addressString, tx:newTrans)
		try newTrans.commit()
	}
	
	// returns the next pending address from the database
	fileprivate func getNextPendingAddress(tx:borrowing Transaction) throws -> String {
		return try self.date_pendingIP.cursor(tx:tx) { dateCursor in
			return try String(dateCursor.opFirst().value)
		}
	}

	// installs a failed resolution into the database with the corresponding error that caused the info to fail
	public func installFailedResolve(address:String, error:Swift.Error) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		let failDate = bedrock.Date.Seconds()
		let errorString = String(describing:error)
		let ipHash = try IPHash(ipString: EncodedString(address))
		
		try self.resolveFailDate_ipHash.setEntry(key: failDate, value: ipHash, flags: [], tx: newTrans)
		try self.ipHash_resolveFailDate.setEntry(key: ipHash, value: failDate, flags: [], tx: newTrans)
		try self.ipHash_resolveFailMessage.setEntry(key: ipHash, value: EncodedString(errorString), flags: [], tx: newTrans)
		try self.ipHash_ipString.setEntry(key: ipHash, value: EncodedString(address), flags: [], tx: newTrans)
		log.debug("installed resolution failure info", metadata:["address": "\(address)", "failMessage": "\(errorString)"])
		try newTrans.commit()
	}
	
	// removes a failed resolution from the database
	fileprivate func uninstallFailedResolve(address:EncodedString, tx:borrowing Transaction) throws {
		let ipHash = try IPHash(ipString: address)

		let resolveFailDate = try self.ipHash_resolveFailDate.loadEntry(key:ipHash, tx: tx)
		try self.resolveFailDate_ipHash.deleteEntry(key:resolveFailDate, tx:tx)
		try self.ipHash_resolveFailDate.deleteEntry(key:ipHash, tx:tx)
		try self.ipHash_resolveFailMessage.deleteEntry(key:ipHash, tx:tx)
		try self.ipHash_ipString.deleteEntry(key:ipHash, tx:tx)
	}
	
	fileprivate func rotateStaleRecords(tx:borrowing Transaction) throws {
		// failed records that are a month old will rotate back into the pending section of the databse (they will be removed as failed records before this happens)
		try self.resolveFailDate_ipHash.cursor(tx:tx) { failedIPDateCursor in
			try self.ipHash_ipString.cursor(tx:tx) { hashStringCursor in
				let targetThreshold = bedrock.Date.Seconds().subtractingTimeInterval(2629800)
				for (dateVal, hashVal) in failedIPDateCursor {
					if dateVal < targetThreshold {
						let addressString = try hashStringCursor.opSet(key: hashVal)
						try self.uninstallFailedResolve(address: addressString, tx: tx)
						try self.installPending(address: addressString, tx: tx)
					} else {
						return
					}
				}
			}
		}
		
		// succeeded record that are two months old will have a 1 in 5 chance of being rotated back into the database for re-resolution (addresses will not be removed from the "success" database while they are in the pending section of the database
		try self.resolveSuccessDate_ipHash.cursor(tx:tx) { succeededIPDateCursor in
			try self.ipHash_ipString.cursor(tx:tx) { hashStringCursor in
				let targetThreshold = bedrock.Date.Seconds().subtractingTimeInterval(5259600)
				for (dateVal, hashVal) in succeededIPDateCursor {
					let randomVal = UInt8.random(in:0..<4)
					if dateVal < targetThreshold {
						let addressString = try hashStringCursor.opSet(key: hashVal)
						log.trace("resolved ip has crossed the stale threshold.", metadata:["ip": "\(String(addressString))"])
						if (randomVal == 0) {
							log.trace("random number generator selected this record to re-resolve.", metadata:["ip":"\(String(addressString))"])
							do {
								try self.installPending(address:addressString, tx:tx)
							} catch LMDBError.keyExists {}
						} else {
							log.trace("random number generator did not select this record to re-resolve.", metadata:["ip":"\(String(addressString))"])
						}
					} else {
						return
					}
				}
			}
		}
	}
	
	fileprivate func getResolveStatus(ipString:String, tx:borrowing Transaction) throws -> ResolveStatus {
		let ipHash = try IPHash(ipString: EncodedString(ipString))
		do {
			let resolvedInfo = try self.ipHash_resolvedData.loadEntry(key: ipHash, tx: tx)
			return .resolved(resolvedInfo)
		} catch LMDBError.notFound {
			do {
				let failMessage = try self.ipHash_resolveFailMessage.loadEntry(key: ipHash, tx: tx)
				return .failedResolving(String(failMessage))
			} catch LMDBError.notFound {
				if (try self.pendingIP_date.containsEntry(key:EncodedString(ipString), tx:tx) == true) {
					return .resolving
				} else {
					throw LMDBError.notFound
				}
			}
		}
	}
	
	public func getResolveStatus(address:AddressV4) throws -> ResolveStatus {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try self.getResolveStatus(ipString:address.string, tx:newTrans)
	}
	
	public func getResolveStatus(address:AddressV6) throws -> ResolveStatus {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try self.getResolveStatus(ipString:address.string, tx:newTrans)
	}
	
	public func getResolveStatus(address:String) throws -> ResolveStatus {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try self.getResolveStatus(ipString:address, tx:newTrans)
	}
	
	public func installAddress(ipv4:AddressV4) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		do {
			let resolveStatus = try self.getResolveStatus(ipString:ipv4.string, tx:newTrans)
			log.debug("installing an address that is already accounted for. no action taken.", metadata:["ip": "\(ipv4.string)", "status": "\(String(describing:resolveStatus))"])
			return
		} catch LMDBError.notFound {
			log.debug("installing address in database", metadata:["ip": "\(ipv4.string)"])
			try self.installPending(ipv4:ipv4, tx:newTrans)
		}
		try newTrans.commit()
	}
	
	public func installAddress(ipv6:AddressV6) throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		do {
			let resolveStatus = try self.getResolveStatus(ipString:ipv6.string, tx:newTrans)
			log.debug("installing an address that is already accounted for. no action taken.", metadata:["ip": "\(ipv6.string)", "status": "\(String(describing:resolveStatus))"])
			return
		} catch LMDBError.notFound {
			log.debug("installing address in database", metadata:["ip": "\(ipv6.string)"])
			try self.installPending(ipv6:ipv6, tx:newTrans)
		}
		try newTrans.commit()
	}
	
	public func getNextPendingAddress() throws -> String? {
		let newTrans = try Transaction(env: env, readOnly: true)
		do {
			return try self.getNextPendingAddress(tx: newTrans)
		} catch LMDBError.notFound {
			return nil
		}
	}
	
	public func setupMainLoop() throws -> String? {
		let newTrans = try Transaction(env: env, readOnly: false)
		try self.rotateStaleRecords(tx:newTrans)
		var accessKey:String
		do {
			accessKey = String(try self.metadata.loadEntry(key: EncodedString(Metadatas.ipstackAccessKey.rawValue), as: EncodedString.self, tx: newTrans)!)
		} catch LMDBError.notFound {
			log.debug("resolver Task exiting. no access key configured.")
			return nil
		}
		try newTrans.commit()
		return accessKey
	}
	
	public func installResolved(currentAddress: EncodedString, resolvedIPInfo: ResolvedIPInfo) throws -> String? {
		let newTrans = try Transaction(env: env, readOnly: false)
		try self.uninstallPending(addressString: currentAddress, tx: newTrans)
		try self.installSuccessfulResolve(address: currentAddress, resolution: resolvedIPInfo, tx: newTrans)
		var accessKey:String
		do {
			accessKey = String(try self.metadata.loadEntry(key: EncodedString(Metadatas.ipstackAccessKey.rawValue), as: EncodedString.self, tx: newTrans)!)
		} catch LMDBError.notFound {
			log.debug("resolver Task exiting. no access key configured.")
			return nil
		}
		try newTrans.commit()
		return accessKey
	}

	public func getIPStackKey() throws -> EncodedString {
		let newTrans = try Transaction(env: env, readOnly: true)
		return try self.metadata.loadEntry(key: EncodedString(Metadatas.ipstackAccessKey.rawValue), as: EncodedString.self, tx: newTrans)!
	}
		
	public func setIPStackKey(_ apiKey:String) throws { 
		let newTrans = try Transaction(env: env, readOnly: false)
		try self.metadata.setEntry(key: EncodedString(Metadatas.ipstackAccessKey.rawValue), value: EncodedString(apiKey), flags: [], tx: newTrans)
		try newTrans.commit()
	}
}
