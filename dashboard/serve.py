"""Serve the finished evaluator pages and the latest published run on loopback."""
import argparse
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

root=Path(__file__).resolve().parent
class Handler(SimpleHTTPRequestHandler):
    def translate_path(self,path):
        if urlsplit(path).path=="/alerts.json":
            return str(root/"alerts.json")
        return super().translate_path(path)
    def list_directory(self,path):
        self.send_error(HTTPStatus.NOT_FOUND)
    def end_headers(self):
        self.send_header("Cache-Control","no-store")
        super().end_headers()

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--port",type=int,default=8099)
    port=p.parse_args().port
    site=root/"site"
    if not (site/"demo/index.html").is_file():
        p.error("Build the Estate static pages with dashboard/build_estate.py and deploy dashboard/site first")
    with ThreadingHTTPServer(("127.0.0.1",port),partial(Handler,directory=str(site))) as server:
        print(f"Dashboard http://127.0.0.1:{port}",flush=True)
        server.serve_forever()
