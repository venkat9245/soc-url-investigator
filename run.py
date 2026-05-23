#!/usr/bin/env python3

import os
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import create_app

app = create_app()


def init_database():
    from app import db
    from app.models.user import User

    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@soc.local",
                role="admin"
            )

            admin.set_password("S0C_Admin_2026!")

            db.session.add(admin)
            db.session.commit()

            print("[+] Admin user created")
            print("[+] Username: admin")
            print("[+] Password: S0C_Admin_2026!")

        else:
            print("[*] Admin user already exists")

        print("[+] Database initialized successfully")


def main():
    parser = argparse.ArgumentParser(
        description="SOC URL Investigator Dashboard"
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind address"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", 5000)),
        help="Port"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )

    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialize database and create admin user"
    )

    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Run without SSL"
    )

    args = parser.parse_args()

    if args.init_db:
        init_database()
        return

    proto = "https" if not args.no_ssl else "http"

    print(
        f"[*] SOC URL Investigator starting on "
        f"{proto}://{args.host}:{args.port}"
    )

    ssl_ctx = None if args.no_ssl else "adhoc"

    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            ssl_context=ssl_ctx
        )

    except TypeError as e:

        if "cryptography" in str(e):
            print("[!] SSL unavailable. Running without SSL.")

            app.run(
                host=args.host,
                port=args.port,
                debug=args.debug,
                ssl_context=None
            )


if __name__ == "__main__":
    main()
