import QuickLMDB
import Foundation
import SwiftSMTP

struct SMTPdb {
	enum Metadatas:String {
		case host = "smtp_host" //String
		case username = "smtp_username" //String
		case password = "smtp_password" //String
		case port = "smtp_port" //UInt16
		
		case sendas_email = "smtp_sendas_email" // String
		case sendas_name = "smtp_sendas_name" // String
	}
	
	static func getSMTPEnabled(daemon:DaemonDB) throws -> Bool {
		return try daemon.metadata.containsEntry(key:Metadatas.host.rawValue, tx:nil)
	}
	
	static func assignSMTPSettings(daemon:DaemonDB, sendAsName:String, sendAsEmail:String, host:String, port:UInt16, username:String, password:String) async throws {
		let serverConfig = Configuration.Server(hostname:host, port:Int(port), encryption:.startTLS(Configuration.Server.Encryption.StartTLSMode.always))
		let creds = SwiftSMTP.Configuration.Credentials(username:username, password:password)
		let mailer = Mailer(group:daemon.loopGroup, configuration: Configuration(server:serverConfig, connectionTimeOut:.seconds(15), credentials: creds))
		let newEmail = Email(sender:Email.Contact(name:sendAsName, emailAddress:sendAsEmail), recipients: try daemon.getNotifyUsers(), subject:"SMTP Test Notification", body:.plain("This is a test notification email from the wiremand service."))
		try await mailer.send(email: newEmail)
		
		try daemon.env.transact(readOnly:false) { someTrans in
			try daemon.metadata.setEntry(value:host, forKey:Metadatas.host.rawValue, tx:someTrans)
			try daemon.metadata.setEntry(value:username, forKey:Metadatas.username.rawValue, tx:someTrans)
			try daemon.metadata.setEntry(value:password, forKey:Metadatas.password.rawValue, tx:someTrans)
			try daemon.metadata.setEntry(value:port, forKey:Metadatas.port.rawValue, tx:someTrans)
			try daemon.metadata.setEntry(value:sendAsName, forKey:Metadatas.sendas_name.rawValue, tx:someTrans)
			try daemon.metadata.setEntry(value:sendAsEmail, forKey:Metadatas.sendas_email.rawValue, tx:someTrans)
		}
		try daemon.env.sync()
	}
	
	
}
