"""
Simple login server for testing authenticated scanning
Username: admin
Password: example
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class LoginHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Override to show requests"""
        print(f"[REQUEST] {format % args}")

    def do_GET(self):
        """Handle GET requests"""
        print(f"\n[GET] {self.path}")

        try:
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.send_header("Server", "TestServer/1.0 Python/3.11")
                self.end_headers()
                self.wfile.write(
                    b"""
                    <html><body>
                    <h1>Login Required</h1>
                    <form action="/login" method="post">
                        Username: <input name="username" value="admin"><br>
                        Password: <input name="password" type="password" value="example"><br>
                        <button type="submit">Login</button>
                    </form>
                    </body></html>
                """
                )

            elif self.path == "/dashboard":
                cookie = self.headers.get("Cookie", "")
                print(f"[COOKIE] {cookie}")

                if "session=authenticated" in cookie:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                    self.wfile.write(
                        b"""
                        <html><body>
                        <h1>Welcome to Dashboard!</h1>
                        <p>You are logged in.</p>
                        <a href="/admin">Admin Panel</a>
                        </body></html>
                    """
                    )
                else:
                    self.send_response(403)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>403 - Access Denied - Login Required</h1></body></html>"
                    )

            elif self.path == "/admin":
                cookie = self.headers.get("Cookie", "")
                print(f"[COOKIE] {cookie}")

                if "session=authenticated" in cookie:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                    self.wfile.write(
                        b"""
                        <html><body>
                        <h1>Admin Panel</h1>
                        <p>Secret admin page with XSS vulnerability</p>
                        <form action="/admin/search" method="get">
                            Search: <input name="q" value="test">
                            <button>Search</button>
                        </form>
                        </body></html>
                    """
                    )
                else:
                    print("[!] Access denied - no valid session")
                    self.send_response(403)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                    self.wfile.write(
                        b'<html><body><h1>403 - Access Denied - Login Required</h1><a href="/">Login</a></body></html>'
                    )

            elif self.path.startswith("/admin/search"):
                cookie = self.headers.get("Cookie", "")
                print(f"[COOKIE] {cookie}")

                if "session=authenticated" in cookie:
                    parsed = urlparse(self.path)
                    params = parse_qs(parsed.query)
                    search_term = params.get("q", [""])[0]

                    print(f"[SEARCH] Query: {search_term}")

                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()

                    # XSS VULNERABLE - reflects user input without encoding!
                    html = f"""
                        <html><body>
                        <h1>Search Results</h1>
                        <p>You searched for: {search_term}</p>
                        <p>Results: None found</p>
                        <a href="/admin">Back to Admin</a>
                        </body></html>
                    """
                    self.wfile.write(html.encode())
                else:
                    self.send_response(403)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>403 - Access Denied</h1></body></html>"
                    )

            else:
                # 404 for unknown paths
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.send_header("Server", "TestServer/1.0 Python/3.11")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>404 - Not Found</h1></body></html>")

        except Exception as e:
            print(f"[ERROR] {e}")
            try:
                self.send_response(500)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>500 - Server Error</h1></body></html>"
                )
            except Exception:  # nosec: B110
                pass

    def do_POST(self):
        """Handle POST requests"""
        print(f"\n[POST] {self.path}")

        try:
            if self.path == "/login":
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length).decode("utf-8")
                params = parse_qs(post_data)

                username = params.get("username", [""])[0]
                password = params.get("password", [""])[0]

                print(f"[LOGIN] User: {username}, Pass: {'*' * len(password)}")

                if username == "admin" and password == "example":  # nosec: B105
                    print("[+] Login successful!")
                    self.send_response(302)
                    self.send_header("Location", "/dashboard")
                    self.send_header("Set-Cookie", "session=authenticated; Path=/")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                else:
                    print("[!] Login failed!")
                    self.send_response(401)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Server", "TestServer/1.0 Python/3.11")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Login Failed</h1>"
                        b"<p>Invalid credentials</p>"
                        b'<a href="/">Try Again</a></body></html>'
                    )
            else:
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.send_header("Server", "TestServer/1.0 Python/3.11")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>404 - Not Found</h1></body></html>")

        except Exception as e:
            print(f"[ERROR] {e}")
            try:
                self.send_response(500)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>500 - Server Error</h1></body></html>"
                )
            except Exception:  # nosec: B110
                pass


if __name__ == "__main__":
    try:
        server = HTTPServer(("127.0.0.1", 8080), LoginHandler)
        print("=" * 60)
        print("🔒 VScanX Test Login Server")
        print("=" * 60)
        print("Running on: http://127.0.0.1:8080")
        print("Username:   admin")
        print("Password:   example")
        print("=" * 60)
        print("\nEndpoints:")
        print("  /                - Login page")
        print("  /login           - Login handler (POST)")
        print("  /dashboard       - Dashboard (requires auth)")
        print("  /admin           - Admin panel (requires auth)")
        print("  /admin/search?q= - Search page with XSS vuln (requires auth)")
        print("\nPress Ctrl+C to stop\n")
        print("=" * 60)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[*] Server stopped")
    except Exception as e:
        print(f"\n[!] Server error: {e}")
