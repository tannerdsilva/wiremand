struct NginxExecutor {
    static func serverConfig(domain:String) -> String {
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
        
    }
}
