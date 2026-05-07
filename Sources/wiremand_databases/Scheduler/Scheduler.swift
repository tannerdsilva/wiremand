import RAW
import struct NIOCore.TimeAmount
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import QuickLMDB
import Logging
import struct Foundation.URL
import ServiceLifecycle

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<pid_t>(bigEndian:true)
@MDB_comparable()
public struct EncodedPID:Sendable, Equatable {
	public static func currentPID() -> EncodedPID {
		return EncodedPID(RAW_native:getpid())
	}
}

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
@MDB_comparable()
public struct EncodedDuration:Sendable {}

public struct Scheduler:Sendable {
	/// scheduler uses
	public typealias TaskName = EncodedString
	/// thrown when a task cannot be launched because it is already running on another PID.
	public struct ScheduleAlreadyRunningError:Swift.Error {
		let existingPID:pid_t
	}
	/// thrown when the task ownership is unexpectedly taken from the running PID and claimed by another PID.
	public struct UnexpectedTaskRescheduleError:Swift.Error {
		let hijackingPID:pid_t
	}
	/// thrown when the running PID is found to no longer be the owner of the task name. this is considered an internal
	public struct VanishingTaskOwnershipError:Swift.Error {}
	
	public enum Databases:String {
		case scheduleTasks = "schedule_task_db"
		case scheduleIntervals = "schedule_interval_db"
		case scheduleLastFireDate = "schedule_last_fire_dateprecise_db"
	}
	
	public let log:Logger
	
	public let env:Environment
	
	/// records which PID currently "owns" a given task name
	public let schedule_pid:Database.Strict<TaskName, EncodedPID>
	public let schedule_timeInterval:Database.Strict<TaskName, EncodedDuration>
	public let schedule_lastFireDate:Database.Strict<TaskName, DateUTC.Precise>
	
	public init(base:URL, log:Logger) throws {
		let dbFileName = "task-scheduler-vX.mdb"
		let targetURL = base.appendingPathComponent(dbFileName, isDirectory:false)
		let envSize = size_t(targetURL.getFileSize()) + size_t(1.28e6)
		let makeEnv = try Environment(path:targetURL.path, flags:[.noSubDir, .noReadAhead], mapSize:envSize, maxReaders:32, maxDBs:8, mode:[.ownerReadWrite, .groupRead, .groupExecute])
		let someTrans = try Transaction(env:makeEnv, readOnly:false)
		let pidDB = try Database.Strict<TaskName, EncodedPID>(env:makeEnv, name:Databases.scheduleTasks.rawValue, flags:[.create], tx:someTrans)
		let intervalDB = try Database.Strict<TaskName, EncodedDuration>(env:makeEnv, name:Databases.scheduleIntervals.rawValue, flags:[.create], tx:someTrans)
		let lastFireDateDB = try Database.Strict<TaskName, DateUTC.Precise>(env:makeEnv, name:Databases.scheduleLastFireDate.rawValue, flags:[.create], tx:someTrans)
		do {
			// delete the old date database if it exists
			let oldDateDB = try Database.Strict<TaskName, DateUTC>(env:makeEnv, name:"schedule_last_fire_date_db", flags:[], tx:someTrans)
			try oldDateDB.deleteDatabase(tx:someTrans)
			log.info("successfully deleted old date database", metadata:["old_database":"schedule_last_fire_date_db"])
		} catch LMDBError.notFound {
			// if the database does not exist, then we can ignore this error, as the database is not present, and this is the desired outcome
		} catch let error {
			log.critical("failed to delete old date database", metadata:["error":"\(error)"])
			fatalError("failed to delete old date database: \(error). This is a fatal internal error that should not happen. \(#file):\(#line)")
		}
		try someTrans.commit()
		self.env = makeEnv
		self.schedule_pid = pidDB
		self.schedule_timeInterval = intervalDB
		self.schedule_lastFireDate = lastFireDateDB
		self.log = log
	}
	
	public func runSchedule(name:TaskName, interval:TimeAmount, _ task:@Sendable () async throws -> Void) async throws {
		
		// setup the task
		let encodedInterval = EncodedDuration(RAW_native:UInt32(interval.nanoseconds / 1_000_000_000))
		let myPID = EncodedPID.currentPID()
		
		// logging rituals
		var mutateLogger = log
		mutateLogger[metadataKey:"name"] = "\(name)"
		mutateLogger[metadataKey:"interval"] = "\(interval.nanoseconds / 1_000_000_000)s"
		mutateLogger.info("task launched")
		defer {
			mutateLogger.info("task ended")
		}
		func initializeState() throws -> DateUTC.Precise {
			// determine when the task should run next
			var nextTargetDate:DateUTC.Precise
			do {
				let newTransaction = try Transaction(env:env, readOnly:false)
				mutateLogger.trace("task successfully opened introductory transaction")
				do {
					// try to set the pid for the task name
					try schedule_pid.setEntry(key:name, value:myPID, flags:[.noOverwrite], tx:newTransaction)
				} catch LMDBError.keyExists {
					// if the task is already running, check to see if it is still alive
					let existingPID = try schedule_pid.loadEntry(key:name, tx:newTransaction).RAW_native()
					guard kill(existingPID, 0) != 0 else {
						mutateLogger.warning("task is already running on PID '\(existingPID)'")
						throw ScheduleAlreadyRunningError(existingPID:existingPID)
					}
					try schedule_pid.setEntry(key:name, value:myPID, flags:[], tx:newTransaction)
				}
				mutateLogger.debug("task PID successfully assigned: '\(myPID.RAW_native())'")
				try schedule_timeInterval.setEntry(key:name, value:encodedInterval, flags:[], tx:newTransaction)
				do {
					let lastFireDate = try schedule_lastFireDate.loadEntry(key:name, tx:newTransaction)
					nextTargetDate = lastFireDate.addingTimeInterval(Double(interval.nanoseconds / 1_000_000_000))
					mutateLogger.trace("task has last fire date of \(lastFireDate.timeIntervalSinceUnixDate()).")
				} catch LMDBError.notFound {
					mutateLogger.trace("task has no last fire date, setting to fire the task now")
					nextTargetDate = DateUTC.Precise()
				}
				try newTransaction.commit()
				return nextTargetDate
			} catch let error {
				mutateLogger.error("task failed to initialize due to thrown error.", metadata:["error":"\(error)"])
				throw error
			}
		}

		func applySuccessfulTaskRun(nextTargetDate:inout DateUTC.Precise) throws {
			// write the new timing data to the database
			let someTrans = try Transaction(env:env, readOnly:false)
			mutateLogger.debug("updating task timing data.", metadata:["next_target_date":"\(nextTargetDate.timeIntervalSinceUnixDate())"])
			// write the new fire date
			try schedule_lastFireDate.setEntry(key:name, value:nextTargetDate, flags:[], tx:someTrans)

			// validate that we are still the owner of the schedule name and that we should continue firing it
			do {
				let owningPID = try schedule_pid.loadEntry(key:name, tx:someTrans)
				if owningPID != myPID {
					// if the pid has changed, then the task has been rescheduled, so break out of the main loop
					mutateLogger.error("task \(name) has been rescheduled while this process was running")
					throw UnexpectedTaskRescheduleError(hijackingPID:owningPID.RAW_native())
				} else {
					// pid remained the same, so we can continue, as we are still the owner of the task
					let nowDate = DateUTC.Precise()
					while nextTargetDate <= nowDate {
						nextTargetDate = nextTargetDate.addingTimeInterval(Double(interval.nanoseconds / 1_000_000_000))
						mutateLogger.trace("next target date \(nextTargetDate.timeIntervalSinceUnixDate()) is in the past, incrementing by \(Int(interval.nanoseconds)) seconds")
					}
					// continue the main loop
					mutateLogger.debug("task \(name) will fire next at \(nextTargetDate.timeIntervalSinceUnixDate()), which is ahead of \(nowDate.timeIntervalSinceUnixDate())")
				}
			} catch LMDBError.notFound {
				mutateLogger.warning("task \(name) is no longer scheduled with this pid")
				throw VanishingTaskOwnershipError()
			}
			try someTrans.commit()
		}

		func closureHandler() {
			do {
				let someTrans = try Transaction(env:env, readOnly:false)
				mutateLogger.debug("task is removing itself from the database")
				try schedule_pid.deleteEntry(key:name, tx:someTrans)
				try schedule_timeInterval.deleteEntry(key:name, tx:someTrans)
				try someTrans.commit()
				mutateLogger.trace("successfully removed task from the database")
			} catch let error {
				mutateLogger.critical("task failed to remove itself from the database due to thrown error", metadata:["error":"\(error)"])
			}
		}

		var nextTargetDate = try initializeState()

		// ensure that the task is removed from the database when it is done running
		defer {
			closureHandler()
		}
		// this should transparently throw any errors that are thrown within the users task, as well as any unexpected errors that may be thrown by LMDB.
		// cancellation errors that occurr outside of the users code should NOT cascade outside of this group.
		mainLoop: while true {

			// determine how much time should pass before running the task
			let delayTime = nextTargetDate.timeIntervalSince(DateUTC.Precise())
			if delayTime > 0 {
				// wait for the next target date
				mutateLogger.debug("sleeping task until fire time")
				do {
					// wait for the next target date
					try await cancelWhenGracefulShutdown({
						try await Task.sleep(nanoseconds:UInt64(delayTime * 1e9))
					})
				} catch is CancellationError {
					if Task.isCancelled == true {
						throw CancellationError()
					} else {
						break mainLoop
					}
				}
			} else if delayTime < 0 || delayTime > Double(UInt16.max) || UInt16(delayTime) > interval.nanoseconds / 1_000_000_000 {
				mutateLogger.debug("task will fire immediately")
				// the time to fire has already passed, so it will fire now
				nextTargetDate = DateUTC.Precise()
			}

			// run the task
			mutateLogger.debug("running task.")
			
			// unexpected errors here should cause the task to cancel
			do {
				try await task()
			} catch let error {
				mutateLogger.error("user task block failed with thrown error", metadata:["error":"\(error)"])
				throw error
			}

			try applySuccessfulTaskRun(nextTargetDate:&nextTargetDate)
			
		}
	}
}
