from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Numeric
from flask_login import UserMixin
from datetime import datetime, timezone

db = SQLAlchemy()

#User model for storing user credentials
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    reports = db.relationship('Report', backref='user', lazy=True)

#Report model for storing reports
class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    risk_score = db.Column(db.Float, nullable=False)
    risk_message = db.Column(db.String(10), nullable=False)
    risk_level = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Report {self.id} for User {self.user_id}>'
