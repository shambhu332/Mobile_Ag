from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from fastapi.testclient import TestClient
from mobileag.web.app import app
import json
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(b'SYNTHETIC-LOOPBACK-MARKER')
    def log_message(self,*a):pass
server=HTTPServer(('127.0.0.1',0),Handler)
t=Thread(target=server.serve_forever,daemon=True);t.start()
try:
    r=TestClient(app).post('/api/apis/test',json={'url':f'http://127.0.0.1:{server.server_port}/synthetic'})
    print(json.dumps({'http':r.status_code,'mode':r.json()['mode'],'returned_loopback_marker':r.json()['body']=='SYNTHETIC-LOOPBACK-MARKER'},indent=2))
finally: server.shutdown();server.server_close();t.join()
