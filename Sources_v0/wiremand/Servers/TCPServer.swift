//
//  EchoServer.swift
//  CNIOAtomics
//
//  Created by Jonathan Wong on 4/25/18.
//

import Foundation
import NIO
import bedrock

enum EchoServerError: Error {
	case invalidHost
	case invalidPort
}


class TCPPortManager {
	static var logger = makeDefaultLogger(label:"tcp-manager")
	
	fileprivate let bindHost:String
	
	let printDB:PrintDB
	
	var servers = [UInt16:TCPServer]()
	
	init(bindHost:String, printDB:PrintDB) throws {
		self.bindHost = bindHost
		self.printDB = printDB
		Self.logger.trace("instance initialized")
		Task.detached { [weak self] in
			guard let self = self else {
				return
			}
			try await self.updatePrinters()
		}
	}
	
	func updatePrinters() async throws {
		// gather info and compare
		let startingPorts = Set(self.servers.keys)
		let authorizedPrinters = try printDB.getAuthorizedPrinterInfo()
		let endingPorts = Set(authorizedPrinters.compactMap({ $0.port }))
		let comparePorts = Delta<UInt16>(start:startingPorts, end:endingPorts)
		
		Self.logger.debug("updating printers with TCP sockets...", metadata:["drop_ports":"\(comparePorts.exclusiveStart)", "add_ports":"\(comparePorts.exclusiveEnd)"])
		// remove any of the ports that have been dropped
		for curDropPort in comparePorts.exclusiveStart {
			servers.removeValue(forKey:curDropPort)
		}
		
		// add any of the new ports that have been added
		for curAddPort in comparePorts.exclusiveEnd {
			self.servers[curAddPort] = try await TCPServer(host:bindHost, port:curAddPort, db:printDB)
		}
	}
}

class TCPServer {
	static var logger = makeDefaultLogger(label:"tcp-server")
	
	private let port:UInt16
	private let group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
	private let channel:Channel
	
	init(host:String, port:UInt16, db:PrintDB) async throws {
		self.port = port
		let bootstrap = ServerBootstrap(group: group)
			// Specify backlog and enable SO_REUSEADDR for the server itself
			.serverChannelOption(ChannelOptions.backlog, value: 256)
			.serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			
			// Set the handlers that are appled to the accepted Channels
			.childChannelInitializer { channel in
				// Ensure we don't read faster than we can write by adding the BackPressureHandler into the pipeline.
				return channel.pipeline.addHandler(BackPressureHandler()).flatMap { v in
					channel.pipeline.addHandler(PrintJobIntakeHandler(port:port, db:db))
				}
			}
			
			// Enable TCP_NODELAY and SO_REUSEADDR for the accepted Channels
			.childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
			.childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			.childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
			.childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())
		channel = try await bootstrap.bind(host:host, port:Int(port)).get()
		Self.logger.debug("instance initialized", metadata:["port":"\(port)"])
	}
	
	deinit {
		Self.logger.debug("instance deinitialized. closing socket.", metadata:["port":"\(port)"])
		channel.close()
	}
}

class PrintJobIntakeHandler:ChannelInboundHandler {
	typealias InboundIn = ByteBuffer
	typealias OutboundOut = ByteBuffer
	
	let portNumber:UInt16
	let database:PrintDB
	var buildData = Data()
	
	init(port:UInt16, db:PrintDB) {
		self.portNumber = port
		self.database = db
	}
	func channelRegistered(context: ChannelHandlerContext) {
		context.fireChannelRegistered()
	}
	
	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		var buffer = unwrapInboundIn(data)
		let readableBytes = buffer.readableBytes
		if let received = buffer.readData(length:readableBytes) {
			buildData += received
		}
	}
	
	func channelReadComplete(context: ChannelHandlerContext) {
		context.flush()
	}
	
	func channelUnregistered(context:ChannelHandlerContext) {
		if buildData.count > 0 {
			try! database.newPrintJob(port:portNumber, date:Date(), data:buildData)
			buildData = Data()
		}
	}
	
	func errorCaught(context: ChannelHandlerContext, error: Error) {
		context.close(promise: nil)
	}
}
