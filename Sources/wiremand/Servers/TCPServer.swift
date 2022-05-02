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

class EchoServer {
	private let group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
	private var host: String?
	var port: Int?
	
	init(host: String, port: Int) {
		self.host = host
		self.port = port
	}
	
	func start() throws {
		guard let host = host else {
			throw EchoServerError.invalidHost
		}
		guard let port = port else {
			throw EchoServerError.invalidPort
		}
		do {
			let channel = try serverBootstrap.bind(host: host, port: port).wait()
			print("Listening on \(String(describing: channel.localAddress))...")
			try channel.closeFuture.wait()
		} catch let error {
			throw error
		}
	}
	
	func stop() {
		do {
			try group.syncShutdownGracefully()
		} catch let error {
			print("Error shutting down \(error.localizedDescription)")
			exit(0)
		}
		print("Client connection closed")
	}
	
	private var serverBootstrap: ServerBootstrap {
		return ServerBootstrap(group: group)
			.serverChannelOption(ChannelOptions.backlog, value: 256)
			.serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			.childChannelInitializer { channel in
				channel.pipeline.addHandler(BackPressureHandler()).flatMap { v in
					channel.pipeline.addHandler(EchoHandler())
				}
			}
			.childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
			.childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
			.childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
			.childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())
	}
}

class EchoHandler:ChannelInboundHandler {
	typealias InboundIn = ByteBuffer
	typealias OutboundOut = ByteBuffer
	func channelRead(ctx: ChannelHandlerContext, data: NIOAny) {
		var buffer = unwrapInboundIn(data)
		let readableBytes = buffer.readableBytes
		if let received = buffer.readString(length:readableBytes) {
			print(received)
		}
		
		ctx.write(data, promise: nil)
	}
	
	func channelReadComplete(ctx: ChannelHandlerContext) {
		print(Colors.Magenta("TCP read complete"))
		ctx.flush()
	}
	
	func errorCaught(ctx: ChannelHandlerContext, error: Error) {
		print("error: \(error.localizedDescription)")
		ctx.close(promise: nil)
	}
}
