#!/usr/bin/env python3
from app import db
from datetime import datetime, timezone

class Indicator(db.Model):
    __tablename__ = "indicators"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("url_cases.id"), nullable=False)
    indicator_type = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(500), nullable=False, index=True)
    context = db.Column(db.Text, default="")
    severity = db.Column(db.String(10), default="medium")
    source = db.Column(db.String(50), default="static_analysis")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.Index("idx_indicator_type_value", "indicator_type", "value"),)

    def to_dict(self):
        return {
            "id": self.id, "case_id": self.case_id,
            "type": self.indicator_type, "value": self.value,
            "context": self.context, "severity": self.severity,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Indicator {self.indicator_type}:{self.value[:40]}>"
