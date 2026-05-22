#!/usr/bin/env python3
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from pathlib import Path

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"

def create_app(config_override=None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SOC_SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///" + str(Path(__file__).parent.parent / "data" / "soc_url.db")
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    if config_override:
        app.config.update(config_override)
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)

    # Register JSON filter for templates
    app.jinja_env.filters["from_json"] = lambda v: (__import__("json").loads(v) if isinstance(v, str) and v.strip() and v != "{}" else (v if isinstance(v, dict) else {}))

    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.api import api_bp
    from app.routes.settings import settings_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    register_error_handlers(app)
    setup_logging(app)
    with app.app_context():
        from app.models.user import User
        from app.models.url_case import URL_Case
        from app.models.indicator import Indicator
        from app.models.apikey import APIKey
        db.create_all()
    return app

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(e):
        return {"error": "Not found", "status": 404}, 404
    @app.errorhandler(500)
    def server_error(e):
        return {"error": "Internal server error", "status": 500}, 500
    @app.errorhandler(403)
    def forbidden(e):
        return {"error": "Forbidden", "status": 403}, 403

def setup_logging(app):
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "soc_url_investigator.log"
    handler = RotatingFileHandler(log_file, maxBytes=50*1024*1024, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info("SOC URL Investigator starting...")
