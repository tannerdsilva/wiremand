
import NIO
import ServiceLifecycle
import Logging
import bedrock_ip
import Hummingbird

public struct HTTPWebService:Service {
	public struct Context:BaseRequestContext, RequestContext {
	    public var coreContext:Hummingbird.CoreRequestContext
	    public init(channel:NIOCore.Channel, logger: Logging.Logger) {
			self.coreContext = Hummingbird.CoreRequestContext(allocator:channel.allocator, logger:logger)
	    }
	}
	public struct HelloWorldResponder:HTTPResponder {
	    public func respond(to request: HummingbirdCore.Request, context: HTTPWebService.Context) async throws -> HummingbirdCore.Response {
			return HummingbirdCore.Response(status:.ok, body:ResponseBody())
	    }

	    public typealias Context = HTTPWebService.Context
	}
	private let elg:EventLoopGroup
	public init(eventLoopGroup:EventLoopGroup, bindV4:AddressV4, bindV6:AddressV6, port:UInt16) {
		self.elg = eventLoopGroup
		let mainRouter = Router(context:Context.self)
		mainRouter.on("/hello", method:.get, responder:HelloWorldResponder())
		
		let v4Config = ApplicationConfiguration(address:.hostname(String(bindV4), port:Int(port)))
		let v6Config = ApplicationConfiguration(address:.hostname(String(bindV6), port:Int(port)))

		// let appV4 = Application(configuration:v4Config, eventLoopGroup:self.elg)
	}

	public func run() async throws {
		
	}
	
}