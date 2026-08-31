import http.client
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 11434

UPSTREAM_HOST = os.environ["OPENAI_UPSTREAM_HOST"]
UPSTREAM_PORT = int(os.environ.get("OPENAI_UPSTREAM_PORT", "443"))
UPSTREAM_PATH = os.environ.get("OPENAI_UPSTREAM_PATH", "").rstrip("/")
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

ALLOWED_PATH = "/v1/chat/completions"
MAX_BODY_SIZE = 20 * 1024 * 1024  # 20 MiB

upstream_path = f"{UPSTREAM_PATH}{ALLOWED_PATH}"

class OpenAIProxyHandler(BaseHTTPRequestHandler):
    server_version = "LLMEgress/1.0"

    def _send_error(self, status: int, message: str) -> None:
        body = f"{message}\n".encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != ALLOWED_PATH:
            self._send_error(403, "Forbidden")
            return

        content_length_header = self.headers.get("Content-Length")
        if content_length_header is None:
            self._send_error(411, "Content-Length required")
            return

        try:
            content_length = int(content_length_header)
        except ValueError:
            self._send_error(400, "Invalid Content-Length")
            return

        if content_length < 0 or content_length > MAX_BODY_SIZE:
            self._send_error(413, "Request body too large")
            return

        body = self.rfile.read(content_length)

        upstream = None

        try:
            upstream = http.client.HTTPSConnection(
                host=UPSTREAM_HOST,
                port=UPSTREAM_PORT,
                timeout=180,
            )

            headers = {
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": self.headers.get(
                    "Content-Type",
                    "application/json",
                ),
                "Accept": self.headers.get("Accept", "application/json"),
                "Content-Length": str(len(body)),
                "User-Agent": "sandbox-llm-egress/1.0",
            }

            upstream.request(
                "POST",
                upstream_path,
                body=body,
                headers=headers,
            )

            response = upstream.getresponse()

            self.send_response(response.status)

            excluded_headers = {
                "connection",
                "keep-alive",
                "transfer-encoding",
                "content-encoding",
            }

            for key, value in response.getheaders():
                if key.lower() in excluded_headers:
                    continue
                self.send_header(key, value)

            self.end_headers()

            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()

        except Exception as exc:
            print(
                f"[llm-egress] upstream request failed: {exc}",
                flush=True,
            )
            self._send_error(502, "Bad Gateway")

        finally:
            if upstream is not None:
                upstream.close()

    def do_GET(self) -> None:
        self._send_error(403, "Forbidden")

    def do_PUT(self) -> None:
        self._send_error(403, "Forbidden")

    def do_DELETE(self) -> None:
        self._send_error(403, "Forbidden")

    def do_PATCH(self) -> None:
        self._send_error(403, "Forbidden")

    def do_HEAD(self) -> None:
        self._send_error(403, "Forbidden")

    def log_message(self, fmt: str, *args) -> None:
        print(f"[llm-egress] {self.address_string()} - {fmt % args}", flush=True)


def main() -> None:
    server = ThreadingHTTPServer(
        (LISTEN_HOST, LISTEN_PORT),
        OpenAIProxyHandler,
    )

    print(
        f"[llm-egress] listening on {LISTEN_HOST}:{LISTEN_PORT}, "
        f"upstream={UPSTREAM_HOST}:{UPSTREAM_PORT}",
        flush=True,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()