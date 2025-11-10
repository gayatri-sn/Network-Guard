# server.py (updated version)
from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHandler(BaseHTTPRequestHandler):
    
    # This new method handles GET requests
    def do_GET(self):
        print("\n--- Server received a GET request, serving the HTML form. ---")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        # Open and send the HTML file back to the browser
        with open('test_form.html', 'rb') as f:
            self.wfile.write(f.read())

    # This existing method handles POST requests
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print("\n--- Server received POST data ---")
        print(post_data.decode('utf-8'))
        print("\n")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'<h1>Success!</h1><p>Data received by local server!</p>')

print("[*] Starting local test server on http://localhost:8000")
server = HTTPServer(('localhost', 8000), SimpleHandler)
server.serve_forever()