import Foundation
import QuickLMDB

actor LoggerDB {
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
