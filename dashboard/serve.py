#!/usr/bin/env python3
"""
Dashboard server (Person B). Standard library only.

Serves the dashboard directory on LOOPBACK ONLY (127.0.0.1) so nothing is
exposed on the network. It serves alerts.json (produced by summarize.py) and
index.html. Run from the repo root:

    python dashboard/serve.py            # http://127.0.0.1:8099
    python dashboard/serve.py --port 9000

Demo hygiene: re-run summarize.py after each attack run to refresh alerts.json,
then reload the page. The page shows the run-id + timestamp so a stale view is obvious.
"""
import argparse
import http.server
import os
import socketserver

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    os.chdir(HERE)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")  # never show a stale run
            super().end_headers()

        def log_message(self, *a):
            pass

    with socketserver.TCPServer(("127.0.0.1", args.port), Handler) as httpd:
        print(f"Dashboard on http://127.0.0.1:{args.port}  (loopback only, Ctrl+C to stop)")
        print("serving:", HERE)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")


if __name__ == "__main__":
    main()
