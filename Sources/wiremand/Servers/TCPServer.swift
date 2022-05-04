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
	
	init(host:String, port:UInt16) throws {
		let bootstrap = ServerBootstrap(group: group)
			// Specify backlog and enable SO_REUSEADDR for the server itself
			.serverChannelOption(ChannelOptions.backlog, value: 256)
			.serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			
			// Set the handlers that are appled to the accepted Channels
			.childChannelInitializer { channel in
				print(Colors.magenta("__ server init"))
				// Ensure we don't read faster then we can write by adding the BackPressureHandler into the pipeline.
				return channel.pipeline.addHandler(BackPressureHandler()).flatMap { v in
					channel.pipeline.addHandler(PrintJobIntakeHandler())
				}
			}
			
			// Enable TCP_NODELAY and SO_REUSEADDR for the accepted Channels
			.childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
			.childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			.childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
			.childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())
		channel = try bootstrap.bind(host:host, port:Int(port)).wait()
		print("SERVER IS BOUND")
	}
	
	func stop() {
		channel.close()
	}
	
	deinit {
		print("DEINIT THING")
	}
}

class PrintJobIntakeHandler:ChannelInboundHandler {
	typealias InboundIn = ByteBuffer
	typealias OutboundOut = ByteBuffer
	
	func channelRegistered(context: ChannelHandlerContext) {
		context.fireChannelRegistered()
	}
	
	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		print(Colors.Magenta("data is being read from the socket"))
		var buffer = unwrapInboundIn(data)
		let readableBytes = buffer.readableBytes
		if let received = buffer.readString(length:readableBytes) {
			print(Colors.Magenta("\(received.count)"))
		}
		
		context.write(data, promise: nil)
	}
	
	func channelReadComplete(context: ChannelHandlerContext) {
		print(Colors.Magenta("TCP read complete"))
		context.flush()
	}
	
	func channelUnregistered(context:ChannelHandlerContext) {
		print(Colors.Red("TCP deregistered"))
	}
	
	func errorCaught(context: ChannelHandlerContext, error: Error) {
		print("error: \(error.localizedDescription)")
		context.close(promise: nil)
	}
}
