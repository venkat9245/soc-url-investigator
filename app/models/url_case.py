#!/usr/bin/env python3

from app import db
from datetime import datetime, timezone
import uuid


class URL_Case(db.Model):

    __tablename__ = "url_cases"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    case_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4())
    )

    url = db.Column(
        db.Text,
        nullable=False
    )

    submitted_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        default="pending"
    )

    priority = db.Column(
        db.String(10),
        default="medium"
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    risk_level = db.Column(
        db.String(10),
        default="unknown"
    )

    notes = db.Column(
        db.Text,
        default=""
    )

    tags = db.Column(
        db.String(500),
        default=""
    )

    vt_result = db.Column(
        db.Text,
        default="{}"
    )

    urlscan_result = db.Column(
        db.Text,
        default="{}"
    )

    abuseipdb_result = db.Column(
        db.Text,
        default="{}"
    )

    static_analysis = db.Column(
        db.Text,
        default="{}"
    )

    screenshot_path = db.Column(
        db.String(500),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    completed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    indicators = db.relationship(
        "Indicator",
        backref="case",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )

    # -----------------------------
    # Helper Methods
    # -----------------------------

    def is_high_risk(self):
        return self.risk_score >= 75

    def is_completed(self):
        return self.status == "completed"

    def get_tags(self):
        return self.tags.split(",") if self.tags else []

    def to_dict(self):

        return {

            "id": self.id,

            "case_id": self.case_id,

            "url": self.url,

            "submitted_by": self.submitted_by,

            "status": self.status,

            "priority": self.priority,

            "risk_score": self.risk_score,

            "risk_level": self.risk_level,

            "notes": self.notes,

            "tags": self.get_tags(),

            "created_at": (
                self.created_at.isoformat()
                if self.created_at else None
            ),

            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at else None
            ),

            "completed_at": (
                self.completed_at.isoformat()
                if self.completed_at else None
            ),

            "indicator_count": self.indicators.count(),
        }

    def __repr__(self):

        return (
            f"<URL_Case "
            f"{self.case_id[:8]} "
            f"[{self.status}] "
            f"score={self.risk_score}>"
        )
