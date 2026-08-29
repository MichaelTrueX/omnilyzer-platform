import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg

RELEASE = json.loads(Path("/app/release.json").read_text())


def config():
    required = ("STAGE_NAME", "PUBLIC_MARKER", "DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD_FILE")
    missing = [name for name in required if not os.environ.get(name)]
    secret_file = os.environ.get("DB_PASSWORD_FILE", "")
    if secret_file and not Path(secret_file).is_file():
        missing.append("DB_PASSWORD_FILE_CONTENT")
    return missing


def connect():
    password = Path(os.environ["DB_PASSWORD_FILE"]).read_text().strip()
    return psycopg.connect(
        host=os.environ["DB_HOST"], dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"], password=password, connect_timeout=2,
    )


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/livez":
            return self.reply(200, {"status": "alive"})
        if self.path == "/version":
            return self.reply(200, {
                "release": RELEASE["release"], "source_revision": RELEASE["source_revision"],
                "stage": os.environ.get("STAGE_NAME", ""),
                "required_schema_version": RELEASE["required_schema_version"],
            })
        if self.path == "/config":
            return self.reply(200, {"stage": os.environ.get("STAGE_NAME", ""), "public_marker": os.environ.get("PUBLIC_MARKER", "")})
        if self.path == "/readyz":
            missing = config()
            if missing:
                return self.reply(503, {"status": "not ready", "reason": "runtime configuration incomplete"})
            try:
                with connect() as conn:
                    found = {row[0] for row in conn.execute("SELECT migration_id FROM schema_migrations")}
                required = set(RELEASE["required_migrations"])
                if not required.issubset(found):
                    return self.reply(503, {"status": "not ready", "reason": "required migrations absent"})
            except Exception:
                return self.reply(503, {"status": "not ready", "reason": "database gate failed"})
            return self.reply(200, {"status": "ready"})
        if self.path == "/data":
            try:
                with connect() as conn:
                    rows = conn.execute("SELECT id, name FROM deployment_items ORDER BY id").fetchall()
                return self.reply(200, {"items": [{"id": row[0], "name": row[1]} for row in rows]})
            except Exception:
                return self.reply(503, {"error": "database query failed"})
        return self.reply(404, {"error": "not found"})

    def log_message(self, _format, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
