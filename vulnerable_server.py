"""
Simple Vulnerable Web Server for Testing VScanX
WARNING: Only run on localhost for testing!
"""

import html
import textwrap
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class VulnerableHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        # Home page
        if parsed_path.path == "/" or parsed_path.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            html_content = textwrap.dedent("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>VScanX Test Server</title>
                <style>
                    body { font-family: Arial; max-width: 800px; margin: 50px auto; }
                    .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
                    h2 { color: #667eea; }
                    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
                </style>
            </head>
            <body>
                <h1>🔓 VScanX Vulnerable Test Server</h1>
                <p>This server contains intentional vulnerabilities for testing VScanX.</p>

                <div class="card">
                    <h2>Test Endpoints:</h2>
                    <ul>
                        <li><a href="/search?q=test">Search Page (Vulnerable to XSS)</a></li>
                        <li><a href="/profile?name=John">Profile Page (Vulnerable to XSS)</a></li>
                        <li><a href="/comment?text=hello">Comment Page (Vulnerable to XSS)</a></li>
                    </ul>
                </div>

                <div class="card">
                    <h2>Test Commands:</h2>
                    <code>python vscanx.py -t "http://127.0.0.1:8080/search?q=test" -s web --skip-warning</code><br><br>
                    <code>python vscanx.py -t "http://127.0.0.1:8080/profile?name=user" -s web --skip-warning</code>
                </div>

                <p><strong>⚠️ WARNING:</strong> This server is intentionally vulnerable. Only use for testing!</p>
            </body>
            </html>
            """).strip()
            self.wfile.write(html_content.encode())

        # Vulnerable search page - REFLECTED XSS
        elif parsed_path.path == "/search":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            query = params.get("q", [""])[0]

            # VULNERABLE: Direct insertion without sanitization
            html_content = textwrap.dedent(f"""
            <!DOCTYPE html>
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: {query}</p>
                <p>No results found.</p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """).strip()
            self.wfile.write(html_content.encode())

        # Vulnerable profile page - REFLECTED XSS
        elif parsed_path.path == "/profile":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            name = params.get("name", ["Guest"])[0]

            # VULNERABLE: Direct insertion without sanitization
            html_content = textwrap.dedent(f"""
            <!DOCTYPE html>
            <html>
            <head><title>User Profile</title></head>
            <body>
                <h1>Welcome, {name}!</h1>
                <p>This is your profile page.</p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """).strip()
            self.wfile.write(html_content.encode())

        # Vulnerable comment page - REFLECTED XSS
        elif parsed_path.path == "/comment":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            text = params.get("text", [""])[0]

            # VULNERABLE: Direct insertion in different context
            html_content = textwrap.dedent(f"""
            <!DOCTYPE html>
            <html>
            <head><title>Comments</title></head>
            <body>
                <h1>Comment Posted</h1>
                <div style="border: 1px solid #ccc; padding: 10px;">
                    <strong>Your comment:</strong><br>
                    {text}
                </div>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """).strip()
            self.wfile.write(html_content.encode())

        # Safe page - NO XSS (for comparison)
        elif parsed_path.path == "/safe":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            query = params.get("q", [""])[0]
            safe_query = html.escape(query)  # SAFE: Properly escaped

            html_content = textwrap.dedent(f"""
            <!DOCTYPE html>
            <html>
            <head><title>Safe Search</title></head>
            <body>
                <h1>Safe Search Results</h1>
                <p>You searched for: {safe_query}</p>
                <p>This page is NOT vulnerable (input is escaped).</p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """).strip()
            self.wfile.write(html_content.encode())

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>404 Not Found</h1>")

    def log_message(self, format, *args):
        """Custom log format"""
        print(f"[SERVER] {self.address_string()} - {format % args}")


def run_server(port=8080):
    """Run the vulnerable test server"""
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, VulnerableHandler)

    print("=" * 60)
    print("VScanX Vulnerable Test Server")
    print("=" * 60)
    print(f"Server running at: http://127.0.0.1:{port}/")
    print("WARNING: This server is intentionally vulnerable!")
    print("Only run on localhost for testing purposes!")
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[*] Server stopped")
        httpd.shutdown()


if __name__ == "__main__":
    run_server(8080)
