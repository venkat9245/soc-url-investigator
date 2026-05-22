#!/usr/bin/env python3
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models.url_case import URL_Case
from app.models.indicator import Indicator
from app.services.url_analyzer import URLAnalyzer
from app.services.threat_intel import ThreatIntelService
from datetime import datetime, timezone
import json

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
@login_required
def index():
    total_cases = URL_Case.query.count()
    pending = URL_Case.query.filter_by(status="pending").count()
    completed = URL_Case.query.filter_by(status="completed").count()
    escalated = URL_Case.query.filter_by(status="escalated").count()
    critical = URL_Case.query.filter(URL_Case.risk_level == "critical").count()
    recent_cases = URL_Case.query.order_by(URL_Case.created_at.desc()).limit(10).all()
    return render_template("pages/dashboard.html",
        total_cases=total_cases, pending=pending,
        completed=completed, escalated=escalated, critical=critical,
        recent_cases=[c.to_dict() for c in recent_cases])

@main_bp.route("/submit", methods=["GET", "POST"])
@login_required
def submit_url():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        priority = request.form.get("priority", "medium")
        notes = request.form.get("notes", "")
        if not url:
            flash("URL is required", "danger")
            return render_template("pages/submit.html")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        case = URL_Case(url=url, submitted_by=current_user.id, priority=priority, notes=notes, status="pending")
        db.session.add(case)
        db.session.commit()
        flash(f"URL submitted for investigation - Case #{case.case_id[:8]}", "success")
        return redirect(url_for("main.case_detail", case_id=case.case_id))
    return render_template("pages/submit.html")

@main_bp.route("/cases")
@login_required
def case_list():
    status_filter = request.args.get("status", "all")
    priority_filter = request.args.get("priority", "all")
    search = request.args.get("search", "")
    query = URL_Case.query
    if status_filter != "all":
        query = query.filter_by(status=status_filter)
    if priority_filter != "all":
        query = query.filter_by(priority=priority_filter)
    if search:
        query = query.filter(URL_Case.url.contains(search))
    cases = query.order_by(URL_Case.created_at.desc()).all()
    return render_template("pages/cases.html",
        cases=[c.to_dict() for c in cases],
        status_filter=status_filter, priority_filter=priority_filter, search=search)

@main_bp.route("/case/<case_id>")
@login_required
def case_detail(case_id):
    case = URL_Case.query.filter_by(case_id=case_id).first_or_404()
    indicators = Indicator.query.filter_by(case_id=case.id).all()
    return render_template("pages/case_detail.html", case=case, indicators=[i.to_dict() for i in indicators])

@main_bp.route("/case/<case_id>/analyze", methods=["POST"])
@login_required
def analyze_case(case_id):
    case = URL_Case.query.filter_by(case_id=case_id).first_or_404()
    case.status = "analyzing"
    db.session.commit()

    try:
        # Step 1: Static analysis
        analyzer = URLAnalyzer(case.url)
        static = analyzer.run_static_analysis()
        dns_info = analyzer.run_dns_lookup()
        whois_info = analyzer.run_whois_lookup()
        static["dns"] = dns_info
        static["whois"] = whois_info
        case.static_analysis = json.dumps(static)

        # Step 2: Threat intel (will use DB-stored API keys)
        intel = ThreatIntelService()
        ips = dns_info.get("ips", [])
        threats = intel.aggregate(case.url, ips)

        # Save each threat intel result to the case
        if "virustotal" in intel.results:
            case.vt_result = json.dumps(intel.results["virustotal"])
        if "urlscan" in intel.results:
            case.urlscan_result = json.dumps(intel.results["urlscan"])
        if "abuseipdb" in intel.results:
            case.abuseipdb_result = json.dumps(intel.results["abuseipdb"])

        # Step 3: Risk scoring
        score, level, factors = analyzer.calculate_risk_score(threats)
        case.risk_score = score
        case.risk_level = level

        # Step 4: Extract and save IOCs
        iocs = analyzer.generate_iocs()
        for ioc_data in iocs:
            indicator = Indicator(
                case_id=case.id,
                indicator_type=ioc_data["type"],
                value=ioc_data["value"],
                context=ioc_data["context"],
                severity=ioc_data["severity"],
                source="static_analysis",
            )
            db.session.add(indicator)

        # Step 5: Complete
        case.status = "completed"
        case.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        flash("Analysis completed successfully", "success")

    except Exception as e:
        case.status = "pending"
        db.session.commit()
        flash(f"Analysis failed: {str(e)}", "danger")
        import traceback
        traceback.print_exc()

    return redirect(url_for("main.case_detail", case_id=case.case_id))

@main_bp.route("/case/<case_id>/escalate", methods=["POST"])
@login_required
def escalate_case(case_id):
    if not current_user.can_escalate():
        flash("You do not have permission to escalate cases", "danger")
        return redirect(url_for("main.case_detail", case_id=case_id))
    case = URL_Case.query.filter_by(case_id=case_id).first_or_404()
    case.status = "escalated"
    db.session.commit()
    flash(f"Case {case.case_id[:8]} escalated", "success")
    return redirect(url_for("main.case_detail", case_id=case.case_id))

@main_bp.route("/case/<case_id>/notes", methods=["POST"])
@login_required
def update_notes(case_id):
    case = URL_Case.query.filter_by(case_id=case_id).first_or_404()
    notes = request.form.get("notes", "")
    case.notes = notes
    db.session.commit()
    flash("Notes updated", "success")
    return redirect(url_for("main.case_detail", case_id=case.case_id))
