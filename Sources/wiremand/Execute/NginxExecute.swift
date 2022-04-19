import Foundation
import SystemPackage
struct NginxExecutor {
    fileprivate static func serverConfig(domain:String) -> String {
        return """
server {
    listen 443 ssl;
    server_name \(domain);
    ssl_certificate /etc/letsencrypt/live/\(domain)/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/\(domain)/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/\(domain)/chain.pem;
    location / {
        include /etc/nginx/proxy_params;
        proxy_pass http://wiremandv4;
    }
}
server {
    listen [::]:443 ssl;
    server_name \(domain);
    ssl_certificate /etc/letsencrypt/live/\(domain)/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/\(domain)/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/\(domain)/chain.pem;
    location / {
        include /etc/nginx/proxy_params;
        proxy_pass http://wiremandv6;
    }
}
server {
    listen 80;
    server_name \(domain);
    root /var/www/html;
}
"""
    }
    
    static func install(domain:String) throws {
        let newDomainConfigFile = try FileDescriptor.open("/etc/nginx/sites-enabled/\(domain).conf", .writeOnly, options: [.truncate, .create], permissions: [.ownerReadWrite, .groupReadWrite, .otherRead])
        try newDomainConfigFile.closeAfter({
            try newDomainConfigFile.writeAll(Self.serverConfig(domain: domain).utf8)
        })
    }
    
    static func reload() throws {
        let getPid = try Data(contentsOf:URL(fileURLWithPath:"/run/nginx.pid"))
        let aspid = pid_t(String(data:getPid, encoding:.utf8)!)!
        guard kill(aspid, SIGHUP) == 0 else {
            fatalError("unable to reload nginx")
        }
    }
}
