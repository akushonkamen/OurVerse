#!/usr/bin/env python3
import http.server
import ssl
import socketserver
import os

# 设置端口
PORT = 8443

# 创建HTTPS服务器
class HTTPServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        
        # 创建SSL上下文
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        
        # 包装socket
        self.socket = context.wrap_socket(self.socket, server_side=True)

# 创建请求处理器
Handler = http.server.SimpleHTTPRequestHandler

# 启动服务器
with HTTPServer(("0.0.0.0", PORT), Handler) as httpd:
    print(f"HTTPS服务器启动在 https://localhost:{PORT}")
    print(f"移动端访问地址: https://192.168.101.11:{PORT}")
    print("注意：由于使用自签名证书，浏览器会显示安全警告")
    print("请点击'高级' -> '继续访问'来允许访问")
    print("按 Ctrl+C 停止服务器")
    httpd.serve_forever() 