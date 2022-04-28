import QuickLMDB
import Foundation
import CLMDB

class PrintServer {
    actor Logger {
        struct Event {
            let date:Date
            let smacHash:Data
            let eventMessage:String
            let additionalData:[String:String]
        }
        enum Databases:String {
            case date_uid = "date_uid"               // Date:String
            case uid_eventData = "uid_eventData"     // String:[String:String]
            case uid_smacHash = "uid_smacHash"          // String:Data
            case uid_message = "uid_message"            // String:String
        }
        
        let env:Environment
        let date_uid:Database
        let uid_eventData:Database
        let uid_smacHash:Database
        let uid_message:Database
        
        var syncTask:Task<Void, Swift.Error>? = nil
        
        init(directory:URL) throws {
            let makeEnv = try Environment(path:directory.appendingPathComponent("printerlogs-dbi").path, flags:[.noSubDir, .noSync])
            let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
                let date_uid:Database = try makeEnv.openDatabase(named:Databases.date_uid.rawValue, flags:[.create], tx:someTrans)
                let uid_eventData = try makeEnv.openDatabase(named:Databases.uid_eventData.rawValue, flags:[.create], tx:someTrans)
                let uid_smacHash = try makeEnv.openDatabase(named:Databases.uid_smacHash.rawValue, flags:[.create], tx:someTrans)
                let uid_message = try makeEnv.openDatabase(named:Databases.uid_message.rawValue, flags:[.create], tx:someTrans)
                return [date_uid, uid_eventData, uid_smacHash, uid_message]
            }
            self.env = makeEnv
            self.date_uid = dbs[0]
            self.uid_eventData = dbs[1]
            self.uid_smacHash = dbs[2]
            self.uid_message = dbs[3]
        }
        
        fileprivate func clearTask() {
            self.syncTask = nil
        }
        
        fileprivate func launchAsyncTask() {
            if self.syncTask == nil {
                self.syncTask = Task.detached(operation: { [getEnv = env] in
                    try await Task.sleep(nanoseconds:5000000000)
                    try getEnv.sync(force:true)
                    await self.clearTask()
                })
            }
        }
        
        nonisolated func document(event:Event) async throws {
            try await withUnsafeThrowingContinuation { (runCont:UnsafeContinuation<Void, Swift.Error>) in
                do {
                    try env.transact(readOnly:false) { someTrans in
                        // generate a unique id
                        var newUID = UUID().uuidString
                        while try uid_eventData.containsEntry(key:newUID, tx:someTrans) == true {
                            newUID = UUID().uuidString
                        }
                        
                        // write it
                        try date_uid.setEntry(value:newUID, forKey:event.date, flags:[.noOverwrite], tx:someTrans)
                        try uid_eventData.setEntry(value:event.additionalData, forKey:newUID, flags:[.noOverwrite], tx:someTrans)
                        try uid_smacHash.setEntry(value:event.smacHash, forKey:newUID, flags:[.noOverwrite], tx:someTrans)
                        try uid_message.setEntry(value:event.eventMessage, forKey:newUID, flags:[.noOverwrite], tx:someTrans)
                    }
                    runCont.resume()
                } catch let error {
                    runCont.resume(throwing:error)
                }
            }
            await self.launchAsyncTask()
        }
        
        nonisolated func getEvents(until pastDate:Date, smacHash:Data? = nil) throws -> [Event] {
            try env.transact(readOnly:true) { someTrans in
                let timelineCursor = try date_uid.cursor(tx:someTrans)
                let eventDataCursor = try uid_eventData.cursor(tx:someTrans)
                let smacHashCursor = try uid_smacHash.cursor(tx:someTrans)
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

                        let smacHashVal = Data(try smacHashCursor.getEntry(.set, key:item.value).value)!
                        let eventDataVal = try eventDataCursor.getEntry(.set, key:item.value).value
                        let eventMessageVal = try messageCursor.getEntry(.set, key:item.value).value
                        
                        if (smacHash == nil || smacHash! == smacHashVal) {
                            buildEvents.append(Event(date:getDate, smacHash:smacHashVal, eventMessage:String(eventMessageVal)!, additionalData:Dictionary<String, String>(eventDataVal)!))
                        }
                    } while getDate > pastDate
                    
                } catch LMDBError.notFound {}
                return buildEvents
            }
        }
        
        deinit {
            try? env.sync(force:true)
        }
    }
    /*
    let env:Environment
    let metadata:Database
    let tcpPortNumber_smacHash:Database
    let smacHash_tcpPortNumber:Database
    let smacHash_remoteAddress:Database
    let smacHash_macAddress:Database
    let smacHash_serialData:Database
    let smacHash_status:Database
    let smacHash_userAgent:Database
    let smacHash_printJobDate:Database
    let printJobHash_printJobData:Database
    
    init(directory:URL, startPort:UInt16, endPort:UInt16) throws {
        let makeEnv = try Environment(path:directory.appendingPathComponent("print-dbi").path, flags:[.noSubDir])
        try makeEnv.transact(readOnly:false) { someTrans in
            
        }
    }*/
}
