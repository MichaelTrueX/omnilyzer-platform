import hashlib
import os
from pathlib import Path

import psycopg

LOCK_ID = 7007007
MIGRATIONS = Path(os.environ.get("MIGRATIONS_DIR", "/app/migrations"))


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    password = Path(os.environ["DB_PASSWORD_FILE"]).read_text().strip()
    with psycopg.connect(host=os.environ["DB_HOST"], dbname=os.environ["DB_NAME"], user=os.environ["DB_USER"], password=password) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (migration_id text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())")
            conn.commit()
            recorded = dict(conn.execute("SELECT migration_id, checksum FROM schema_migrations"))
            paths = sorted(MIGRATIONS.glob("*.sql"))
            for path in paths:
                digest = checksum(path)
                if path.name in recorded and recorded[path.name] != digest:
                    raise RuntimeError(f"checksum mismatch for {path.name}")
                if path.name not in recorded:
                    with conn.transaction():
                        conn.execute(path.read_text())
                        conn.execute("INSERT INTO schema_migrations (migration_id, checksum) VALUES (%s, %s)", (path.name, digest))
                    print(f"applied {path.name}")
                else:
                    print(f"verified {path.name}")
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
            conn.commit()


if __name__ == "__main__":
    main()
