#!/usr/bin/env python3
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from datetime import datetime, timezone

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            flash(f"Welcome back, {user.username}", "success")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("pages/login.html")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for("auth.login"))

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not all([username, email, password]):
            flash("All fields are required", "danger")
            return render_template("pages/register.html")
        if password != confirm:
            flash("Passwords do not match", "danger")
            return render_template("pages/register.html")
        if User.query.filter_by(username=username).first():
            flash("Username already taken", "danger")
            return render_template("pages/register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return render_template("pages/register.html")
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("pages/register.html")
