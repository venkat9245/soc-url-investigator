#!/usr/bin/env python3
from flask import Blueprint, request, jsonify
from app import db
from app.models.url_case import URL_Case
from app.models.indicator import Indicator
import json

api_bp = Blueprint("api", __name__)

@api_bp.route("/submit", methods=["POST"])
def api_submit_url():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    url = data.get("url", "").strip()
    priority = data.get("priority", "medium")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    case = URL_Case(url=url, submitted_by=1, priority=priority, status="pending")
    db.session.add(case)
    db.session.commit()
    return jsonify({"status": "submitted", "case_id": case.case_id, "url": url}), 201

@api_bp.route("/case/<case_id>", methods=["GET"])
def api_get_case(case_id):
    case = URL_Case.query.filter_by(case_id=case_id).first()
    if not case:
        return jsonify({"error": "Case not found"}), 404
    result = case.to_dict()
    result["static_analysis"] = json.loads(case.static_analysis) if case.static_analysis else {}
    result["vt_result"] = json.loads(case.vt_result) if case.vt_result else {}
    result["urlscan_result"] = json.loads(case.urlscan_result) if case.urlscan_result else {}
    indicators = Indicator.query.filter_by(case_id=case.id).all()
    result["indicators"] = [i.to_dict() for i in indicators]
    return jsonify(result)

@api_bp.route("/search", methods=["GET"])
def api_search():
    url = request.args.get("url", "")
    status = request.args.get("status", "")
    query = URL_Case.query
    if url:
        query = query.filter(URL_Case.url.contains(url))
    if status:
        query = query.filter_by(status=status)
    cases = query.order_by(URL_Case.created_at.desc()).limit(50).all()
    return jsonify({"total": len(cases), "results": [c.to_dict() for c in cases]})

@api_bp.route("/stats", methods=["GET"])
def api_stats():
    total = URL_Case.query.count()
    by_status = {s: URL_Case.query.filter_by(status=s).count() for s in ("pending", "analyzing", "completed", "escalated", "false_positive")}
    by_risk = {l: URL_Case.query.filter_by(risk_level=l).count() for l in ("unknown", "low", "medium", "high", "critical")}
    return jsonify({"total_cases": total, "by_status": by_status, "by_risk_level": by_risk})
