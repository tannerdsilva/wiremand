//
//  EchoServer.swift
//  CNIOAtomics
//
//  Created by Jonathan Wong on 4/25/18.
//

import Foundation
import NIO

enum EchoServerError: Error {
	case invalidHost
	case invalidPort
}

class TCPServer {
	private let group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
	private let channel:Channel
	
	init(host:String, port:UInt16, db:PrintDB) throws {
		let bootstrap = ServerBootstrap(group: group)
			// Specify backlog and enable SO_REUSEADDR for the server itself
			.serverChannelOption(ChannelOptions.backlog, value: 256)
			.serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			
			// Set the handlers that are appled to the accepted Channels
			.childChannelInitializer { channel in
				// Ensure we don't read faster then we can write by adding the BackPressureHandler into the pipeline.
				return channel.pipeline.addHandler(BackPressureHandler()).flatMap { v in
					channel.pipeline.addHandler(PrintJobIntakeHandler(port:port, db:db))
				}
			}
			
			// Enable TCP_NODELAY and SO_REUSEADDR for the accepted Channels
			.childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
			.childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			.childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
			.childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())
		channel = try bootstrap.bind(host:host, port:Int(port)).wait()
	}
	
	func stop() {
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
