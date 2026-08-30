import Foundation
import SwiftSlash
import Clibnftables
import SystemPackage
import Logging
import wiremand_databases

/// A class for executing NFTable commands.
/// Create an instance of the class and call the run function.
///
/// Commands passed into the class DO NOT need the starting "nft" before the command. For example,
/// "nft add table newTable" should be passed into run as "add table newTable."
internal final class NFTables {
	// typical logging bullshit
	fileprivate static func makeLogger() -> Logger {
		var newLogger = Logger(label:"nft-ctx")
		#if DEBUG
		newLogger.logLevel = .trace
		#else
		newLogger.logLevel = .info
		#endif
		return newLogger
	}
	fileprivate static let logger = makeLogger()
	
	// errors associated with this class
	enum Error:Swift.Error {
		case runError
		case outputBufferError
		case nullFHError
	}
	
	// nftables context (primary interaction class for nftables)
	let nft_context = nft_ctx_new(UInt32(NFT_CTX_DEFAULT));
	
	fileprivate let devNull = fopen("/dev/null", "a")
	
	init() throws {
		let outputSetResult = nft_ctx_set_output(nft_context, devNull)
		let errorSetResult = nft_ctx_set_error(nft_context, devNull)
		
		guard outputSetResult != nil && errorSetResult != nil else {
			throw Error.nullFHError
		}
		Self.logger.trace("instance initialized")
	}
	
	func run(commands:[String]) throws {
		let runResult = nft_run_cmd_from_buffer(nft_context, commands.joined(separator:"\n") + "\n")
		guard runResult == 0 else {
			Self.logger.error("unable to run commands from buffer", metadata:["return_code":"\(runResult)"])
			throw Error.runError
		}
		Self.logger.trace("ran \(commands.count) commands", metadata:["return_code":"\(runResult)"])
		guard let outputPointer = nft_ctx_get_output_buffer(nft_context) else {
			Self.logger.error("unable to capture output context")
			throw Error.outputBufferError
		}
		let asString = String(cString:outputPointer)
		Self.logger.debug("successfully pulled output buffer from context", metadata:["length":"\(asString.count)"])
		
	}

	deinit {
		Self.logger.trace("instance deinitialized")
		nft_ctx_free(nft_context);
	}
}

extension NFTables: NftCommandRunner {}
