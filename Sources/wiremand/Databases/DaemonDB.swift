
import QuickLMDB
import Foundation

class DaemonDB {
    static func create(directory:URL, publicHTTPPort:UInt16, internalTCPPort:UInt16) throws {
        let makeEnv = try Environment(path:directory.appendingPathComponent("daemon-dbi").path, flags:[.noSubDir])
        try makeEnv.transact(readOnly:false) { someTrans in
            let makeDB = try makeEnv.openDatabase()
            try makeDB.setEntry(value:publicHTTPPort, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:someTrans)
            try makeDB.setEntry(value:internalTCPPort, forKey:Metadatas.daemonInternalTCPPort.rawValue, tx:someTrans)
        }
    }
    
    enum Error:Swift.Error {
        case daemonAlreadyRunning
    }
    enum Metadatas:String {
        case daemonRunningPID = "_daemonRunningPID" //pid_t
        case daemonPublicListenPort = "_daemonPublicHTTPListenPort" //UInt16
        case daemonInternalTCPPort = "_daemonInternalTCPListenPort" //UInt16
    }
    
    func getPublicHTTPPort() throws -> UInt16 {
       return try main.getEntry(type:UInt16.self, forKey:Metadatas.daemonPublicListenPort.rawValue, tx:nil)!
    }
    
    func getInternalTCPPort() throws -> UInt16 {
        return try main.getEntry(type:UInt16.self, forKey:Metadatas.daemonInternalTCPPort.rawValue, tx:nil)!
    }
    
    let env:Environment
    let main:Database
    
    init(directory:URL) throws {
        let makeEnv = try Environment(path:directory.appendingPathComponent("daemon-dbi").path, flags:[.noSubDir])
        self.main = try makeEnv.transact(readOnly:false) { someTrans in
            let mainDB = try makeEnv.openDatabase(tx:someTrans)
            do {
                let lastPid = try mainDB.getEntry(type:pid_t.self, forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)!
                let checkPid = kill(lastPid, 0)
                guard checkPid != 0 else {
                    throw Error.daemonAlreadyRunning
                }
            } catch LMDBError.notFound {
                try mainDB.setEntry(value:getpid(), forKey:Metadatas.daemonRunningPID.rawValue, tx:someTrans)
            }
            return mainDB
        }
        self.env = makeEnv
    }
    
    deinit {
        try! main.deleteEntry(key:Metadatas.daemonRunningPID.rawValue, tx:nil)
    }
}
