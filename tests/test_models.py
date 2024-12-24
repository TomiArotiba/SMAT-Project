from app import create_app, db  # Ensure db is imported
from app.models import User, Report
from datetime import datetime, timezone

def test_user_model(app):
    with app.app_context():
        user = User(email="test@example.com", password="hashed_password", role="user")
        db.session.add(user)
        db.session.commit()

        retrieved_user = User.query.filter_by(email="test@example.com").first()
        assert retrieved_user.email == "test@example.com"
        assert retrieved_user.role == "user"

def test_report_model(app):
    with app.app_context():
        user = User(email="user@example.com", password="hashed_password", role="user")
        db.session.add(user)
        db.session.commit()

        report = Report(
            user_id=user.id,
            created_at=datetime.now(timezone.utc),
            risk_score=1.5,
            risk_message="Test Risk",
            risk_level="Medium"
        )
        db.session.add(report)
        db.session.commit()

        retrieved_report = Report.query.first()
        assert retrieved_report.risk_score == 1.5
        assert retrieved_report.risk_message == "Test Risk"
