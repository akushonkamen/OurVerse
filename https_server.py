#!/usr/bin/env python3
import http.server
import ssl
import socketserver
import os
import subprocess
import sys
from pathlib import Path

# 设置端口
PORT = 8443

def generate_self_signed_cert():
    """生成自签名SSL证书"""
    cert_file = 'cert.pem'
    key_file = 'key.pem'
    
    # 如果证书文件已存在，直接返回
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("SSL证书文件已存在")
        return
    
    print("正在生成自签名SSL证书...")
    
    # 生成私钥
    subprocess.run([
        'openssl', 'genrsa', '-out', key_file, '2048'
    ], check=True, capture_output=True)
    
    # 生成证书
    subprocess.run([
        'openssl', 'req', '-new', '-x509', '-key', key_file,
        '-out', cert_file, '-days', '365', '-subj',
        '/C=CN/ST=Beijing/L=Beijing/O=SiteExhibition/CN=localhost'
    ], check=True, capture_output=True)
    
    print("SSL证书生成完成")

def find_available_port(start_port):
    """查找可用端口"""
    import socket
    
    for port in range(start_port, start_port + 100):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return None

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

def main():
    # 检查并生成SSL证书
    try:
        generate_self_signed_cert()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("错误：无法生成SSL证书。请确保已安装OpenSSL。")
        print("macOS安装命令：brew install openssl")
        sys.exit(1)
    
    # 查找可用端口
    available_port = find_available_port(PORT)
    if available_port is None:
        print(f"错误：无法找到可用端口（尝试范围：{PORT}-{PORT+99}）")
        sys.exit(1)
    
    if available_port != PORT:
        print(f"端口 {PORT} 被占用，使用端口 {available_port}")
    
    # 启动服务器
    try:
        with HTTPServer(("0.0.0.0", available_port), Handler) as httpd:
            print(f"HTTPS服务器启动在 https://localhost:{available_port}")
            print(f"移动端访问地址: https://192.168.101.6:{available_port}")
            print("注意：由于使用自签名证书，浏览器会显示安全警告")
            print("请点击'高级' -> '继续访问'来允许访问")
            print("按 Ctrl+C 停止服务器")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print(f"服务器启动失败：{e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 