#!/usr/bin/env python3
from app import db
from datetime import datetime, timezone

class APIKey(db.Model):
    __tablename__ = "api_keys"
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(50), unique=True, nullable=False, index=True)
    api_key = db.Column(db.String(500), nullable=False, default="")
    is_enabled = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    def __repr__(self):
        masked = self.api_key[:8] + "..." if self.api_key and len(self.api_key) > 8 else "(empty)"
        return f"<APIKey {self.service}: {masked}>"
