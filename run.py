#!/usr/bin/env python3
import os
import sys
import argparse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from app import create_app

def main():
    parser = argparse.ArgumentParser(description="SOC URL Investigator Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Port (default: 8443)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--init-db", action="store_true", help="Initialize database and create admin user")
    parser.add_argument("--no-ssl", action="store_true", help="Run without SSL (HTTP only)")
    args = parser.parse_args()

    app = create_app()

    if args.init_db:
        from app import db
        from app.models.user import User
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username="admin").first():
                admin = User(username="admin", email="admin@soc.local", role="admin")
                admin.set_password("S0C_Admin_2026!")
                db.session.add(admin)
                db.session.commit()
                print("[+] Admin user created: admin / S0C_Admin_2026!")
            else:
                print("[*] Admin user already exists")
            print("[+] Database initialized successfully")
        return

    proto = "https" if not args.no_ssl else "http"
    print(f"[*] SOC URL Investigator starting on {proto}://{args.host}:{args.port}")
    
    ssl_ctx = None if args.no_ssl else "adhoc"
    try:
        app.run(host=args.host, port=args.port, debug=args.debug, ssl_context=ssl_ctx)
    except TypeError as e:
        if "cryptography" in str(e):
            print("[!] cryptography library not available. Running without SSL.")
            app.run(host=args.host, port=args.port, debug=args.debug, ssl_context=None)

if __name__ == "__main__":
    main()
