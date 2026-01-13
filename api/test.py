from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<!DOCTYPE html>
<html>
<head><title>CipherGuard</title></head>
<body style="background:#0f1419;color:#fff;font-family:sans-serif;text-align:center;padding:50px;">
<h1 style="color:#00d4ff;">CipherGuard Works!</h1>
<p>Vercel Python is running.</p>
</body>
</html>'''
        self.wfile.write(html.encode())
        return
