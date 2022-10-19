import QuickLMDB
import Foundation
import CLMDB
import NIO
import SwiftSMTP
import SystemPackage
import Logging

extension Task:MDB_convertible {
    public init?(_ value: MDB_val) {
        guard MemoryLayout<Self>.stride == value.mv_size else {
            return nil
        }
        self = value.mv_data.bindMemory(to:Self.self, capacity:1).pointee
    }
    
    public func asMDB_val<R>(_ valFunc: (inout MDB_val) throws -> R) rethrows -> R {
        return try withUnsafePointer(to:self, { unsafePointer in
            var newVal = MDB_val(mv_size:MemoryLayout<Self>.stride, mv_data:UnsafeMutableRawPointer(mutating:unsafePointer))
            return try valFunc(&newVal)
        })
    }
}

class DaemonDB {
	fileprivate static func makeLogger() -> Logger {
		var newLogger = Logger(label:"daemon-db")
		#if DEBUG
			newLogger.logLevel = .trace
		#else
			newLogger.logLevel = .info
		#endif
		return newLogger
	}
	internal static let logger = makeLogger()
	
	static func create(directory:URL, publicHTTPPort:UInt16, notify:Email.Contact) throws -> Environment {
		let makeEnvPath = directory.appendingPathComponent("daemon-dbi")
		let makeEnvLockPath = directory.appendingPathComponent("daemon-dbi-lock")
		
		//verify that the files do not already exist
		if access(makeEnvPath.path, F_OK) == 0 {
			try FileManager.default.removeItem(at:makeEnvPath)
			try FileDescriptor.open(makeEnvPath.path, .writeOnly, options:[.create], permissions:[.ownerReadWriteExecute, .groupReadWriteExecute, .otherRead, .otherExecute]).close()
		}
		if access(makeEnvLockPath.path, F_OK) == 0 {
			try FileManager.default.removeItem(at:makeEnvLockPath)
			try FileDescriptor.open(makeEnvLockPath.path, .writeOnly, options:[.create], permissions:[.ownerReadWriteExecute, .groupReadWriteExecute, .otherReadWriteExecute]).close()
		}
		let makeEnv = try Environment(path:makeEnvPath.path, flags:[.noSubDir], mapSize:75000000000, maxDBs:128, mode: [.ownerReadWriteExecute, .groupReadWriteExecute])
		logger.info("lmdb environment successfully created")
        try makeEnv.transact(readOnly:false) { someTrans in
            let metadata = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[.create], tx:someTrans)
            _ = try makeEnv.openDatabase(named:Databases.scheduleTasks.rawValue, flags:[.create], tx:someTrans)
            _ = try makeEnv.openDatabase(named:Databases.scheduleInterval.rawValue, flags:[.create], tx:someTrans)
            _ = try makeEnv.openDatabase(named:Databases.scheduleLastFireDate.rawValue, flags:[.create], tx:someTrans)
			let notifyDB = try makeEnv.openDatabase(named:Databases.notifyUsers.rawValue, flags:[.create], tx:someTrans)
			try notifyDB.setEntry(value:notify.emailAddress, forKey:notify.name!, tx:someTrans)
            try metadata.setEntry(value:publicHTTPPort, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:someTrans)
        }
		return makeEnv
    }
    
    enum Databases:String {
        case metadata = "daemon_metadata_db"
        case scheduleTasks = "ddb_schedule_tasks"				// Schedule:Task<(), Swift.Error>
        case scheduleInterval = "ddb_schedule_interval"			// Schedule:TimeInterval
        case scheduleLastFireDate = "ddb_schedule_lastFire"		// Schedule:Date?
		case notifyUsers = "ddb_notify"							// String:String
    }
    enum Error:Swift.Error {
        case daemonAlreadyRunning
        case pidExclusivityNotClaimed
		case databaseNotCreated
		case databaseNotReadable
    }
    enum Metadatas:String {
        case daemonRunningPID = "_daemonRunningPID" //pid_t
        case daemonPublicListenPort = "_daemonPublicHTTPListenPort" //UInt16
    }
    
    nonisolated func getPublicHTTPPort() throws -> UInt16 {
       return try metadata.getEntry(type:UInt16.self, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:nil)!
    }
    
	let loopGroup = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
	
	let readOnly:Bool
	let running:Bool
	
    let env:Environment
    let metadata:Database
    let scheduledTasks:Database
    let scheduleInterval:Database
    let scheduleLastFire:Database
	let notifyDB:Database
	
    let wireguardDatabase:WireguardDatabase
	let printerDatabase:PrintDB?
	let ipdb:IPDatabase
	
    init(running:Bool = true) throws {
		let directory = URL(fileURLWithPath:"/var/lib/wiremand", isDirectory:true)
		
		// define the paths of the database
		let makeEnvPath = directory.appendingPathComponent("daemon-dbi")

		let ro:Bool
		var mdb_flags:Environment.Flags = [.noSync, .noSubDir, .noReadAhead]
		
		//validate the file exists
		if (access(makeEnvPath.path, F_OK | R_OK | X_OK) == 0) {
			if access(makeEnvPath.path, W_OK) != 0 {
				ro = true
				mdb_flags.update(with:.readOnly)
				Self.logger.trace("readonly mode enabled.")
			} else {
				ro = false
				Self.logger.trace("read/write mode enabled.")
			}
		} else {
			throw Error.databaseNotCreated
		}
		
		let makeEnv:Environment
		do {
			makeEnv = try Environment(path:makeEnvPath.path, flags:mdb_flags, mapSize:5000000000, maxDBs:128)
			Self.logger.trace("lmdb environment initialized.")
		} catch let error {
			Self.logger.error("unable to initialize lmdb environment.", metadata:["error":"\(error)"])
			throw error
		}
		
		let dbs = try makeEnv.transact(readOnly:ro) { someTrans -> [Database] in
            let metadataDB = try makeEnv.openDatabase(named:Databases.metadata.rawValue, tx:someTrans)
            let scheduledTasks = try makeEnv.openDatabase(named:Databases.scheduleTasks.rawValue, tx:someTrans)
            let scheduleIntervalDB = try makeEnv.openDatabase(named:Databases.scheduleInterval.rawValue, tx:someTrans)
            let scheduleLastFire = try makeEnv.openDatabase(named:Databases.scheduleLastFireDate.rawValue, tx:someTrans)
			let notifyDB = try makeEnv.openDatabase(named:Databases.notifyUsers.rawValue, tx:someTrans)
			if running {
				do {
					let lastPid = try metadataDB.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
					let checkPid = kill(lastPid, 0)
					guard checkPid != 0 else {
						Self.logger.error("running mode enabled but daemon process already running", metadata:["this_pid":"\(getpid())", "running_pid":"\(lastPid)"])
						throw Error.daemonAlreadyRunning
					}
				} catch LMDBError.notFound {}
				Self.logger.trace("running mode enabled. committing PID in database.", metadata:["this_pid":"\(getpid())"])
				try metadataDB.setEntry(value:getpid(), forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)
				try scheduledTasks.deleteAllEntries(tx:someTrans)
			}
			Self.logger.debug("instance initialized successfully.", metadata:["readonly": "\(ro)", "this_running_pid": "\(running)"])
            return [metadataDB, scheduledTasks, scheduleIntervalDB, scheduleLastFire, notifyDB]
        }
		
        self.env = makeEnv
        self.metadata = dbs[0]
        self.scheduledTasks = dbs[1]
        self.scheduleInterval = dbs[2]
        self.scheduleLastFire = dbs[3]
		self.notifyDB = dbs[4]
        self.wireguardDatabase = try WireguardDatabase(environment:makeEnv)
		let makePrintDB:PrintDB?
		do {
			makePrintDB = try PrintDB(environment:makeEnv, directory:directory, readOnly:ro)
		} catch LMDBError.notFound {
			Self.logger.debug("print db not enabled")
			makePrintDB = nil
		}
		self.printerDatabase = makePrintDB
		self.ipdb = try IPDatabase.init(base:directory)
		self.readOnly = ro
		self.running = running
    }
    enum Schedule:String {
        case latestWireguardHandshakesCheck = "_wg_latestHandshakesCheck"
        case certbotRenewalCheck = "_wg_certbotRenewalCheck"
    }
    nonisolated func launchSchedule(_ schedule:Schedule, interval:TimeInterval, _ task:@escaping @Sendable () async -> Void) throws {
        try env.transact(readOnly:false) { installTaskTrans in
            // validate pid exclusivity for this process
            guard try self.metadata.getEntry(type:pid_t.self, forKey: Metadatas.daemonRunningPID.rawValue, tx:installTaskTrans)! == getpid() else {
                throw Error.pidExclusivityNotClaimed
            }
            
            // assign the interval for this schedule
            try self.scheduleInterval.setEntry(value:interval, forKey:schedule.rawValue, tx:installTaskTrans)
            
            // determine the next fire date for the schedule
            let nextFire:Date
            do {
                let lastDate = try self.scheduleLastFire.getEntry(type:Date.self, forKey:schedule.rawValue, tx:installTaskTrans)!
                nextFire = lastDate.addingTimeInterval(interval)
            } catch LMDBError.notFound {
                nextFire = Date()
            }

            let newTask = Task<(), Swift.Error>.detached { [mdbEnv = env, intervalDB = scheduleInterval, lastFire = scheduleLastFire, referenceDate = nextFire, initInterval = interval] in
                var nextTarget = referenceDate
                var runningInterval = initInterval
                while Task.isCancelled == false {
                    let delayTime = nextTarget.timeIntervalSinceNow
                    if (delayTime > 0) {
                        try await Task.sleep(nanoseconds:1000000000 * UInt64(ceil(delayTime)))
                    } else if (abs(delayTime) > runningInterval) {
                        nextTarget = Date()
                    }
                    await task()
                    (nextTarget, runningInterval) = try mdbEnv.transact(readOnly:false) { someTrans -> (Date, TimeInterval) in
                        try lastFire.setEntry(value:nextTarget, forKey:schedule.rawValue, tx:someTrans)
                        let checkInterval = try intervalDB.getEntry(type:TimeInterval.self, forKey:schedule.rawValue, tx:someTrans)!
                        return (nextTarget.addingTimeInterval(checkInterval), checkInterval)
                    }
                }
            }
            
            try self.scheduledTasks.setEntry(value:newTask, forKey:schedule.rawValue, tx:installTaskTrans)
			try env.sync()
        }
    }
	nonisolated func cancelSchedule(_ schedule:Schedule) throws {
        do {
            try env.transact(readOnly:false) { someTrans in
                let loadTask = try self.scheduledTasks.getEntry(type:Task<(), Swift.Error>.self, forKey:schedule.rawValue, tx:someTrans)!
                loadTask.cancel()
                try self.scheduledTasks.deleteEntry(key:schedule.rawValue, tx:someTrans)
            }
        } catch LMDBError.notFound {}
		try env.sync()
    }
	nonisolated func reloadRunningDaemon() throws {
		do {
			try env.transact(readOnly:true) { someTrans in
				let daemonPID = try metadata.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
				kill(daemonPID, SIGHUP)
			}
		} catch LMDBError.notFound {}
	}
	
	nonisolated func addNotifyUser(name:String, email:String) throws {
		try env.transact(readOnly:false) { someTrans in
			try self.notifyDB.setEntry(value:email, forKey:name, flags:[.noOverwrite], tx:someTrans)
		}
		try env.sync()
	}
	
	nonisolated func getNotifyUsers() throws -> [Email.Contact] {
		return try env.transact(readOnly:true) { someTrans in
			var buildUsers = [Email.Contact]()
			let notifyCursor = try self.notifyDB.cursor(tx:someTrans)
			for curUser in notifyCursor {
				let curEmail = String(curUser.value)!
				let curName = String(curUser.key)!
				buildUsers.append(Email.Contact(name:curName, emailAddress: curEmail))
			}
			return buildUsers
		}
	}
	
	nonisolated func removeNotifyUser(name:String) throws {
		try env.transact(readOnly:false) { someTrans in
			try self.notifyDB.deleteEntry(key:name, tx:someTrans)
		}
		try env.sync()
	}
	
	nonisolated func removeNotifyUser(email:String) throws {
		try env.transact(readOnly:false) { someTrans in
			let notifyCursor = try self.notifyDB.cursor(tx:someTrans)
			for curUserKV in notifyCursor {
				let curEmail = String(curUserKV.value)!
				if curEmail == email {
					try notifyCursor.deleteEntry()
					return
				}
			}
			throw LMDBError.notFound
		}
		try env.sync()
	}
    
    deinit {
		if (running == true && readOnly == false) {
			try! env.transact(readOnly:false) { someTrans in
				let curPID = getpid()
				do {
					let checkPid = try metadata.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
					if curPID == checkPid {
						try metadata.deleteEntry(key:checkPid, tx:someTrans)
						try scheduledTasks.deleteAllEntries(tx:someTrans)
					}
				} catch LMDBError.notFound {}
			}
			try! env.sync(force:true)
		}
    }
}
