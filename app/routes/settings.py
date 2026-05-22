#!/usr/bin/env python3
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models.apikey import APIKey
from datetime import datetime, timezone

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/")
@login_required
def index():
    if not current_user.can_admin():
        flash("Admin access required", "danger")
        return redirect(url_for("main.index"))
    
    keys = APIKey.query.all()
    # Ensure all services exist
    services = ["virustotal", "urlscan", "abuseipdb", "alienvault_otx"]
    for svc in services:
        if not any(k.service == svc for k in keys):
            new_key = APIKey(service=svc, api_key="", is_enabled=False)
            db.session.add(new_key)
    db.session.commit()
    keys = APIKey.query.all()
    
    return render_template("pages/settings.html", keys=keys)

@settings_bp.route("/update", methods=["POST"])
@login_required
def update():
    if not current_user.can_admin():
        flash("Admin access required", "danger")
        return redirect(url_for("main.index"))
    
    service = request.form.get("service", "")
    api_key = request.form.get("api_key", "").strip()
    is_enabled = request.form.get("is_enabled") == "on"
    
    entry = APIKey.query.filter_by(service=service).first()
    if entry:
        entry.api_key = api_key
        entry.is_enabled = is_enabled
        entry.updated_at = datetime.now(timezone.utc)
        entry.updated_by = current_user.id
        db.session.commit()
        flash(f"{service} API key updated", "success")
    else:
        flash(f"Service {service} not found", "danger")
    
    return redirect(url_for("settings.index"))
