
import QuickLMDB
import Foundation

class DaemonDB {
    static func create(directory:URL, publicHTTPPort:UInt16, internalTCPPort_begin:UInt16, internalTCPPort_end:UInt16) throws {
        let makeEnv = try Environment(path:directory.appendingPathComponent("daemon-dbi").path, flags:[.noSubDir])
        try makeEnv.transact(readOnly:false) { someTrans in
            let makeDB = try makeEnv.openDatabase()
            try makeDB.setEntry(value:publicHTTPPort, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:someTrans)
            try makeDB.setEntry(value:internalTCPPort_begin, forKey:Metadatas.daemonInternalTCPPort_begin.rawValue, tx:someTrans)
            try makeDB.setEntry(value:internalTCPPort_end, forKey:Metadatas.daemonInternalTCPPort_end.rawValue, tx:someTrans)
        }
    }
    
    enum Error:Swift.Error {
        case daemonAlreadyRunning
    }
    enum Metadatas:String {
        case daemonRunningPID = "_daemonRunningPID" //pid_t
        case daemonPublicListenPort = "_daemonPublicHTTPListenPort" //UInt16
        case daemonInternalTCPPort_begin = "_daemonInternalTCPListenPort_begin" //UInt16
        case daemonInternalTCPPort_end = "_daemonInternalTCPListenPort_end" //UInt16
    }
    
    func getPublicHTTPPort() throws -> UInt16 {
       return try main.getEntry(type:UInt16.self, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:nil)!
    }
    
    func getInternalTCPPort_Begin() throws -> UInt16 {
        return try main.getEntry(type:UInt16.self, forKey:Metadatas.daemonInternalTCPPort_begin.rawValue, tx:nil)!
    }
    
    func getInternalTCPPort_End() throws -> UInt16 {
        return try main.getEntry(type:UInt16.self, forKey:Metadatas.daemonInternalTCPPort_end.rawValue, tx:nil)!
    }
    
    let env:Environment
    let main:Database
    
    let wireguardDatabase:WireguardDatabase
    
    init(directory:URL, running:Bool = true) throws {
        let makeEnv = try Environment(path:directory.appendingPathComponent("daemon-dbi").path, flags:[.noSubDir])
        self.main = try makeEnv.transact(readOnly:false) { someTrans in
            let mainDB = try makeEnv.openDatabase(tx:someTrans)
            if running {
                do {
                    let lastPid = try mainDB.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
                    let checkPid = kill(lastPid, 0)
                    guard checkPid != 0 else {
                        throw Error.daemonAlreadyRunning
                    }
                } catch LMDBError.notFound {
                    try mainDB.setEntry(value:getpid(), forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)
                }
            }
            return mainDB
        }
        self.env = makeEnv
        self.wireguardDatabase = try WireguardDatabase(directory:directory)
    }
    
    deinit {
        try! env.transact(readOnly:false) { someTrans in
            let curPID = getpid()
            do {
                let checkPid = try main.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
                if curPID == checkPid {
                    try main.deleteEntry(key:checkPid, tx:someTrans)
                }
            } catch LMDBError.notFound {}
        }
    }
}
