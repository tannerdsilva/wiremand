import QuickLMDB
import Foundation
import CLMDB

extension Task:MDB_convertible {
    public init?(_ value: MDB_val) {
        guard MemoryLayout<Self>.stride == value.mv_size else {
            return nil
        }
        self = value.mv_data.bindMemory(to:Self.self, capacity:1).pointee
    }
    
    public init?(noCopy value: MDB_val) {
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
    static func create(directory:URL, publicHTTPPort:UInt16, internalTCPPort_begin:UInt16, internalTCPPort_end:UInt16) throws -> Environment {
		let makeEnv = try Environment(path:directory.appendingPathComponent("daemon-dbi").path, flags:[.noSubDir], mapSize:75000000000, maxDBs:128, mode: [.ownerReadWriteExecute])
        try makeEnv.transact(readOnly:false) { someTrans in
            let metadata = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[.create], tx:someTrans)
            _ = try makeEnv.openDatabase(named:Databases.scheduleTasks.rawValue, flags:[.create], tx:someTrans)
            _ = try makeEnv.openDatabase(named:Databases.scheduleInterval.rawValue, flags:[.create], tx:someTrans)
            _ = try makeEnv.openDatabase(named:Databases.scheduleLastFireDate.rawValue, flags:[.create], tx:someTrans)
            try metadata.setEntry(value:publicHTTPPort, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:someTrans)
            try metadata.setEntry(value:internalTCPPort_begin, forKey:Metadatas.daemonInternalTCPPort_begin.rawValue, tx:someTrans)
            try metadata.setEntry(value:internalTCPPort_end, forKey:Metadatas.daemonInternalTCPPort_end.rawValue, tx:someTrans)
        }
		return makeEnv
    }
    
    enum Databases:String {
        case metadata = "daemon_metadata_db"
        case scheduleTasks = "ddb_schedule_tasks"				// Schedule:Task<(), Swift.Error>
        case scheduleInterval = "ddb_schedule_interval"			// Schedule:TimeInterval
        case scheduleLastFireDate = "ddb_schedule_lastFire"		// Schedule:Date?
    }
    enum Error:Swift.Error {
        case daemonAlreadyRunning
        case pidExclusivityNotClaimed
    }
    enum Metadatas:String {
        case daemonRunningPID = "_daemonRunningPID" //pid_t
        case daemonPublicListenPort = "_daemonPublicHTTPListenPort" //UInt16
        case daemonInternalTCPPort_begin = "_daemonInternalTCPListenPort_begin" //UInt16
        case daemonInternalTCPPort_end = "_daemonInternalTCPListenPort_end" //UInt16
    }
    
    func getPublicHTTPPort() throws -> UInt16 {
       return try metadata.getEntry(type:UInt16.self, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:nil)!
    }
    
    func getInternalTCPPort_Begin() throws -> UInt16 {
        return try metadata.getEntry(type:UInt16.self, forKey:Metadatas.daemonInternalTCPPort_begin.rawValue, tx:nil)!
    }
    
    func getInternalTCPPort_End() throws -> UInt16 {
        return try metadata.getEntry(type:UInt16.self, forKey:Metadatas.daemonInternalTCPPort_end.rawValue, tx:nil)!
    }
    
    let env:Environment
    let metadata:Database
    let scheduledTasks:Database
    let scheduleInterval:Database
    let scheduleLastFire:Database
    
    let wireguardDatabase:WireguardDatabase
	let printerDatabase:PrintDB
	
    init(directory:URL, running:Bool = true) throws {
		let makeEnv = try Environment(path:directory.appendingPathComponent("daemon-dbi").path, flags:[.noSubDir, .noSync], mapSize:75000000000, maxDBs:128)
        let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
            let metadataDB = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[], tx:someTrans)
            let scheduledTasks = try makeEnv.openDatabase(named:Databases.scheduleTasks.rawValue, flags:[], tx:someTrans)
            let scheduleIntervalDB = try makeEnv.openDatabase(named:Databases.scheduleInterval.rawValue, flags:[], tx:someTrans)
            let scheduleLastFire = try makeEnv.openDatabase(named:Databases.scheduleLastFireDate.rawValue, flags:[], tx:someTrans)
            if running {
                do {
                    let lastPid = try metadataDB.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
                    let checkPid = kill(lastPid, 0)
                    guard checkPid != 0 else {
                        throw Error.daemonAlreadyRunning
                    }
                } catch LMDBError.notFound {}
                try metadataDB.setEntry(value:getpid(), forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)
                try scheduledTasks.deleteAllEntries(tx:someTrans)
            }
            return [metadataDB, scheduledTasks, scheduleIntervalDB, scheduleLastFire]
        }
        self.env = makeEnv
        self.metadata = dbs[0]
        self.scheduledTasks = dbs[1]
        self.scheduleInterval = dbs[2]
        self.scheduleLastFire = dbs[3]
        self.wireguardDatabase = try WireguardDatabase(environment:makeEnv)
		self.printerDatabase = try PrintDB(environment:makeEnv, directory:directory)
    }
    enum Schedule:String {
        case latestWireguardHandshakesCheck = "_wg_latestHandshakesCheck"
        case certbotRenewalCheck = "_wg_"
    }
    func launchSchedule(_ schedule:Schedule, interval:TimeInterval, _ task:@escaping @Sendable () async -> Void) throws {
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
        }
    }
    func cancelSchedule(_ schedule:Schedule) throws {
        do {
            try env.transact(readOnly:false) { someTrans in
                let loadTask = try self.scheduledTasks.getEntry(type:Task<(), Swift.Error>.self, forKey:schedule.rawValue, tx:someTrans)!
                loadTask.cancel()
                try self.scheduledTasks.deleteEntry(key:schedule.rawValue, tx:someTrans)
            }
        } catch LMDBError.notFound {}
    }
    
    deinit {
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
    }
}
