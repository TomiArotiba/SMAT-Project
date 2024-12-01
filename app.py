from flask import Flask, redirect, request, url_for, session, render_template_string, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timezone
from tzlocal import get_localzone
import requests
import numpy as np
import joblib
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import re
from weasyprint import HTML
from plotly.subplots import make_subplots
import plotly.graph_objs as go
import plotly.io as pio
import plotly.express as px
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Facebook OAuth configuration
FB_CLIENT_ID = '285793798673387'
FB_CLIENT_SECRET = 'afe12d73a976d18bb941012549d20243'
FB_REDIRECT_URI = 'http://localhost:5000/facebook/callback'
FB_AUTH_URL = 'https://www.facebook.com/dialog/oauth'
FB_TOKEN_URL = 'https://graph.facebook.com/v12.0/oauth/access_token'
FB_API_URL = 'https://graph.facebook.com/v12.0/me'

# Load the trained Random Forest model
rf_model = joblib.load("random_forest_model.pkl")

# Database setup for user accounts
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model for storing user credentials
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Report model for storing reports
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    risk_score = db.Column(db.Float, nullable=False)
    risk_message = db.Column(db.Text, nullable=False)                 

    def __repr__(self):
        return f'<Report {self.id} for User {self.user_id}>'
    
# Initialize the database
with app.app_context():
    db.create_all()

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home page with login/logout links
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        return render_template_string("""
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>SMAT</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            </head>
            <body>
                <div class="container text-center mt-5">
                    <h1>Welcome to SMAT!</h1>
                    <p class="lead">Social Media Analysis Tool for Social Engineering</p>
                    <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
                    <a href="{{ url_for('register') }}" class="btn btn-secondary">Register</a>
                </div>
            </body>
            </html>
        """)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            return "Email already registered"

        # Correct hashing method: pbkdf2:sha256
        new_user = User(email=email, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    
    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Register - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container mt-5">
                <h2>Register</h2>
                <form method="POST" class="mt-3">
                    <div class="form-group">
                        <label for="email">Email address</label>
                        <input type="email" name="email" class="form-control" placeholder="Enter email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Register</button>
                </form>
                <p class="mt-3">Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
            </div>
        </body>
        </html>
    """)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return "Invalid credentials"

        login_user(user)
        return redirect(url_for('login_facebook'))

    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Login - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container mt-5">
                <h2>Login</h2>
                <form method="POST" class="mt-3">
                    <div class="form-group">
                        <label for="email">Email address</label>
                        <input type="email" name="email" class="form-control" placeholder="Enter email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                <p class="mt-3">Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
            </div>
        </body>
        </html>
    """)

# Facebook OAuth login
@app.route('/login_facebook')
def login_facebook():
    return redirect(f"{FB_AUTH_URL}?client_id={FB_CLIENT_ID}&redirect_uri={FB_REDIRECT_URI}&scope=email,public_profile,user_birthday,user_location,user_posts")

# Facebook OAuth callback
@app.route('/facebook/callback')
def facebook_callback():
    code = request.args.get('code')
    token_response = requests.get(FB_TOKEN_URL, params={
        'client_id': FB_CLIENT_ID,
        'client_secret': FB_CLIENT_SECRET,
        'redirect_uri': FB_REDIRECT_URI,
        'code': code
    })
    access_token = token_response.json().get('access_token')
    if access_token:
        session['access_token'] = access_token
    return redirect(url_for('profile'))


# Profile page with risk analysis
@app.route('/profile')
@login_required
def profile():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('login_facebook'))

    profile_response = requests.get(FB_API_URL, params={
        'fields': 'id,name,email,picture,birthday,location,posts.limit(100)',
        'access_token': access_token
    })

    # Error handling for private or restricted profiles
    if 'error' in profile_response.json():
        return render_template_string(f"""
            <div class="alert alert-danger" role="alert">
                Unable to retrieve data for this profile. Please check your privacy settings.
            </div>
            <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        """)

    profile_data = profile_response.json()

    # Check for profiles with no posts
    posts_data = profile_data.get('posts', {}).get('data', [])
    session['total_posts'] = len(posts_data)
    if not posts_data:
        return render_template_string(f"""
            <h2>Profile Information</h2>
            <strong>Name:</strong> {profile_data['name']}<br>
            <strong>Email:</strong> {profile_data.get('email', 'No email')}<br>
            <p>No posts available for analysis.</p>
            <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        """)

    # Initialize risk categories
    personal_data_risk = 0
    financial_risk = 0
    emotional_risk = 0
    risk_message = ""

    #Initialize VADER sentiment analyzer
    analyzer = SentimentIntensityAnalyzer()

    #Lists for categorization
    oversharing_posts = []
    emotional_trigger_posts = []
    personal_data_posts = []
    financial_info_posts = []

    # Analyze posts
    posts_html = "<ul class='list-group mt-3'>"
    sentiments = []
    post_messages = []
    phone_pattern = r'\b(?:\+?(\d{1,3}))?[-.\s]?(\d{1,4})[-.\s]?(\d{1,4})[-.\s]?(\d{1,9})\b'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emotional_triggers = [
        'angry', 'sad', 'frustrated', 'depressed', 'upset', 'anxious',
        'furious', 'rage', 'irritated', 'mad', 'crying', 'grief', 'mourning',
        'heartbroken', 'lonely', 'nervous', 'panic', 'stress', 'worried', 'tense',
        'terrified', 'afraid', 'scared', 'nightmare'
    ]
    oversharing_words = [
        'birthday', 'vacation', 'family', 'wedding', 'graduation', 'party',
        'hospital', 'health', 'accident', 'pregnancy', 'baby', 'anniversary',
        'holiday', 'honeymoon', 'new house', 'new job', 'address', 'school', 'workplace'
    ]
    financial_keywords = [
        'credit card', 'account', 'bank', 'loan', 'password', 'debit card', 'PIN',
        'insurance', 'crypto', 'investment', 'bank name', 'account number',
        'mortgage', 'scam', 'fraud', 'phishing', 'steal', 'hacked'
    ]

    num_sensitive_info = 0  # Initialize counter for sensitive info
    num_emotional_triggers = 0  # Initialize counter for emotional triggers
    num_oversharing = 0  # Initialize counter for oversharing
    
    for post in posts_data:
        message = post.get('message', '').strip()

        if not message or message == "No message":
            continue

        # Sentiment analysis with VADER
        vader_sentiment = analyzer.polarity_scores(message)
        sentiment_score = vader_sentiment['compound']  # Compound score gives overall sentiment

        if sentiment_score != 0: #remove posts with sentiment score 0
            sentiments.append(sentiment_score)
            post_messages.append(message[:50])  # Shortened for display
        
            # Check for emotional trigger words
            if any(trigger in message.lower() for trigger in emotional_triggers):
                emotional_risk += 3
                num_emotional_triggers += 1
                risk_message += f"Potential emotional trigger found in post: {message}<br>"
                emotional_trigger_posts.append(message)

            # Check for oversharing content
            if any(word in message.lower() for word in oversharing_words):
                personal_data_risk += 3
                num_oversharing += 1
                risk_message += f"Potential oversharing found in post: {message}<br>"
                oversharing_posts.append(message)

            if re.search(phone_pattern, message):
                financial_risk += 5  # Higher risk for phone numbers
                num_sensitive_info += 1
                risk_message += f"Potential phone number found in post: {message}<br>"
                personal_data_posts.append(message)

            if re.search(email_pattern, message):
                financial_risk += 3  # Moderate risk for email addresses
                num_sensitive_info += 1
                risk_message += f"Potential email address found in post: {message}<br>"
                personal_data_posts.append(message)

            if any(finance in message.lower() for finance in financial_keywords):
                financial_risk += 5 
                num_sensitive_info += 1
                risk_message += f"Potential financial information found in post: {message}<br>"
                financial_info_posts.append(message)

            # Adjust risk based on sentiment score  
            if sentiment_score <= -0.5:
                emotional_risk += 3  # Strong negative sentiment
            elif sentiment_score < 0:
                emotional_risk += 1  # Mild negative sentiment

            posts_html += f"<li class='list-group-item'>{message} (Sentiment score: {sentiment_score})</li>"
            #posts_html += f"<li class='list-group-item'>{message} (Sentiment score: {sentiment})</li>"

        posts_html += "</ul>"

    # Final risk score based on categorized risks
    total_risk_score = personal_data_risk + financial_risk + emotional_risk

    #Calculate avg_sentiment
    avg_sentiment = np.mean(sentiments) if sentiments else 0

    #Prepare features for the Random Forest model
    features = np.array([[avg_sentiment, num_sensitive_info, num_emotional_triggers, num_oversharing]])

    #Predict risk using the model
    predicted_risk = rf_model.predict(features)[0]

    # Step 5: Combine model prediction with heuristic risks
    # Define weights for heuristic risk categories
    weights = {'emotional': 0.2, 'personal_data': 0.4, 'financial': 0.4}

    # Weighted heuristic risk score
    weighted_heuristic_score = (
        weights['emotional'] * emotional_risk +
        weights['personal_data'] * personal_data_risk +
        weights['financial'] * financial_risk
    )

    #Combine heuristic and model predictions
    final_risk_score = 0.6 * predicted_risk + 0.4 * (weighted_heuristic_score / 10)  # Normalize heuristic score

    # Step 6: Update risk message and display
    if final_risk_score < 1:
        risk_message += "The overall risk level is LOW.<br>"
        print(final_risk_score)
    elif final_risk_score == 1 and final_risk_score < 2:
        risk_message += "The overall risk level is MEDIUM.<br>"
        print(final_risk_score)
    elif final_risk_score >= 2:
        risk_message += "The overall risk level is HIGH.<br>"
        print(final_risk_score)

    risk_level = "LOW" if final_risk_score < 1 else "MEDIUM" if final_risk_score < 2 else "HIGH"

    # Step 7: Update session storage for PDF report
    session['risk_score'] = float(final_risk_score)
    session['risk_message'] = risk_message
    session['risk_level'] = risk_level
    session['num_oversharing'] = num_oversharing
    session['num_emotional_triggers'] = num_emotional_triggers
    session['num_sensitive_info'] = num_sensitive_info
    session['num_financial_info'] = len(financial_info_posts)


    # Save report to the database
    new_report = Report(
        user_id=current_user.id,
        risk_score=final_risk_score,
        risk_message=risk_message
    )
    db.session.add(new_report)
    db.session.commit()
    
    return render_template_string(f"""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Profile - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">

        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <a class="navbar-brand" href="/">SMAT</a>
                <div class="collapse navbar-collapse">
                    <ul class="navbar-nav ml-auto">
                        <li class="nav-item">
                            <a class="nav-link" href="/profile">Profile</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/reports">Reports</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/suggestions">Suggestions</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/logout">Logout</a>
                        </li>
                    </ul>
                </div>
            </nav>
            <div class="container mt-5">
                <!-- Profile Information -->
                <div class="card mb-3">
                    <div class="row no-gutters">
                        <div class="col-md-4">
                            <img src='{profile_data['picture']['data']['url']}' class="card-img" alt="Profile Picture">
                        </div>
                        <div class="col-md-8">
                            <div class="card-body">
                                <h5 class="card-title">{profile_data['name']}</h5>
                                <p class="card-text"><strong>Email:</strong> {profile_data.get('email', 'No email')}</p>
                                <p class="card-text"><strong>Birthday:</strong> {profile_data.get('birthday', 'No birthday')}</p>
                                <p class="card-text"><strong>Location:</strong> {profile_data.get('location', {}).get('name', 'No location')}</p>
                                <p class="card-text"><strong>Risk Level:</strong> {risk_level}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Posts -->
                <h3 class="mt-4">Recent Posts</h3>
                <div>{posts_html}</div>

                <!-- Potential Oversharing -->
                <h3 class="mt-4">Potential Oversharing</h3>
                <ul class="list-group">
                    {"".join(f"<li class='list-group-item'>{post}</li>" for post in oversharing_posts) or "<li class='list-group-item'>No oversharing posts detected.</li>"}
                </ul>

                <!-- Emotional Triggers -->
                <h3 class="mt-4">Potential Emotional Triggers</h3>
                <ul class="list-group">
                    {"".join(f"<li class='list-group-item'>{post}</li>" for post in emotional_trigger_posts) or "<li class='list-group-item'>No emotional triggers detected.</li>"}
                </ul>

                <!-- Personal Data -->
                <h3 class="mt-4">Potential Personal Data (Phone Numbers or Emails)</h3>
                <ul class="list-group">
                    {"".join(f"<li class='list-group-item'>{post}</li>" for post in personal_data_posts) or "<li class='list-group-item'>No personal data detected.</li>"}
                </ul>

                <!-- Financial Information -->
                <h3 class="mt-4">Potential Financial Information</h3>
                <ul class="list-group">
                    {"".join(f"<li class='list-group-item'>{post}</li>" for post in financial_info_posts) or "<li class='list-group-item'>No financial information detected.</li>"}
                </ul>

                <!-- Actions -->
                <div class="mt-4 d-flex justify-content-between mb-5">
                    <a href="/generate_report" class="btn btn-primary">Download Report</a>
                    <a href="/delete_account" class="btn btn-danger">Delete Account</a>
                </div>
            </div>
            <footer class="bg-dark text-white text-center py-3">
                <p>&copy; 2024 SMAT. All Rights Reserved.</p>
            </footer>
        </body>
        </html>
    """)


@app.route('/reports')
@login_required
def reports():
    user_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()

    # Get the local timezone dynamically
    local_timezone = get_localzone()

    # Prepare data for graph
    report_dates = [
        report.created_at.replace(tzinfo=timezone.utc).astimezone(local_timezone) 
        for report in user_reports
    ]
    risk_scores = [report.risk_score for report in user_reports]

    # Format the dates for graph display
    formatted_dates = [date.strftime('%Y-%m-%d %H:%M') for date in report_dates]

    # Create a scatter plot using Plotly
    fig = go.Figure(data=go.Scatter(x=formatted_dates, y=risk_scores, mode='markers', marker=dict(size=10, color='#007bff')))
    fig.update_layout(
        title='Risk Score Trends Over Time',
        xaxis_title='Date & Time',
        yaxis_title='Risk Score',
        template='plotly_white',
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True)
    )

    trend_chart = pio.to_html(fig, full_html=False)

    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Reports - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <a class="navbar-brand" href="/">SMAT</a>
                <div class="collapse navbar-collapse">
                    <ul class="navbar-nav ml-auto">
                        <li class="nav-item">
                            <a class="nav-link" href="/profile">Profile</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/reports">Reports</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/suggestions">Suggestions</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/logout">Logout</a>
                        </li>
                    </ul>
                </div>
            </nav>
            <div class="container mt-5">
                <h2>Your Reports</h2>
                {% if user_reports %}
                    <table class="table table-striped mt-3">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Created At</th>
                                <th>Risk Score</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for report in user_reports %}
                            <tr>
                                <td>{{ loop.index }}</td>
                                <td>{{ report.created_at.replace(tzinfo=timezone.utc).astimezone(local_timezone).strftime('%Y-%m-%d %H:%M') }}</td>
                                <td>{{ report.risk_score }}</td>
                                <td>
                                    <a href="/reports/{{ report.id }}" class="btn btn-primary btn-sm">View</a>
                                    <a href="/generate_report/{{ report.id }}" class="btn btn-primary btn-sm">Download</a>
                                    <a href="/reports/delete/{{ report.id }}" class="btn btn-danger btn-sm">Delete</a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>No reports found. Perform a risk analysis to generate reports.</p>
                {% endif %}
                <div>{{ trend_chart|safe }}</div>
            </div>
            <footer class="bg-dark text-white text-center py-3">
                <p>&copy; 2024 SMAT. All Rights Reserved.</p>
            </footer>
        </body>
        </html>
    """, user_reports=user_reports, trend_chart=trend_chart, local_timezone=local_timezone, timezone=timezone)

@app.route('/reports/<int:report_id>')
@login_required
def view_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return "Unauthorized access", 403
    
    # Convert to local timezone
    local_timezone = get_localzone()
    created_at_local = report.created_at.replace(tzinfo=timezone.utc).astimezone(local_timezone).strftime('%Y-%m-%d %H:%M')

    # Extract statistics
    risk_messages = report.risk_message.split("<br>")
    total_posts_analyzed = session.get('total_posts', 0)
    stats = {
        "oversharing": sum("Potential oversharing" in msg for msg in risk_messages),
        "emotional_triggers": sum("Potential emotional trigger" in msg for msg in risk_messages),
        "personal_data": sum("Potential phone number" in msg or "Potential email address" in msg for msg in risk_messages),
        "financial_risks": sum("Potential financial information" in msg for msg in risk_messages),
    }

    # Separate posts by category
    risk_details = {
        "oversharing": [msg for msg in risk_messages if "Potential oversharing" in msg],
        "emotional_triggers": [msg for msg in risk_messages if "Potential emotional trigger" in msg],
        "personal_data": [msg for msg in risk_messages if "Potential phone number" in msg or "Potential email address" in msg],
        "financial_risks": [msg for msg in risk_messages if "Potential financial information" in msg],
    }


    # Visualization - Bar Chart
    categories = ["Oversharing", "Emotional Triggers", "Personal Data", "Financial Risks"]
    risk_counts = [stats["oversharing"], stats["emotional_triggers"], stats["personal_data"], stats["financial_risks"]]
    risk_level = session.get('risk_level')

    bar_fig = go.Figure([go.Bar(x=categories, y=risk_counts, marker=dict(color='#007bff'))])
    bar_fig.update_layout(
        title="",
        xaxis_title="Risk Category",
        yaxis_title="Count",
        template="plotly_white"
    )
    bar_chart = pio.to_html(bar_fig, full_html=False)

    def format_category(title, items):
        if not items:
            return f"<p class='text-muted'>No posts detected.</p>"
        return "<div class='mt-2'>" + "".join(f"<p>{item}</p>" for item in items) + "</div>"


    return render_template_string(f"""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Report Details - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <style>
                .info-box {{
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 20px;
                    background-color: #f9f9f9;
                }}
                .info-title {{
                    font-size: 1.25rem;
                    font-weight: bold;
                    color: #333;
                }}
                .category-section {{
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 20px;
                    background-color: #f9f9f9;
                }}
                .category-title {{
                    font-size: 1.25rem;
                    font-weight: bold;
                    color: #333;
                }}
                .category-details {{
                    margin-top: 10px;
                }}
                .chart-container {{
                    margin-top: 30px;
                }}
            </style>
        </head>
        <body>
            <div class="container mt-5">
                <h2 class="text-center">Report Details</h2>
                <!-- Date Created and Total Posts Section -->
                <div class="info-box d-flex justify-content-between">
                    <div>
                        <p class="info-title">Date Created</p>
                        <p>{created_at_local}</p>
                    </div>
                    <div class="text-center">
                        <p class="info-title">Risk Level</p>
                        <p>{risk_level}</p>
                    </div>
                    <div>
                        <p class="info-title">Total Posts Analyzed</p>
                        <p>{total_posts_analyzed}</p>
                    </div>
                </div>

                <!-- Risk Breakdown Sections -->
                <div class="category-section">
                    <div class="category-title">Potential Oversharing</div>
                    <div class="category-details">
                        {format_category("Oversharing", risk_details["oversharing"])}
                    </div>
                </div>

                <div class="category-section">
                    <div class="category-title">Potential Emotional Triggers</div>
                    <div class="category-details">
                        {format_category("Emotional Triggers", risk_details["emotional_triggers"])}
                    </div>
                </div>

                <div class="category-section">
                    <div class="category-title">Potential Personal Data</div>
                    <div class="category-details">
                        {format_category("Personal Data", risk_details["personal_data"])}
                    </div>
                </div>

                <div class="category-section">
                    <div class="category-title">Potential Financial Information</div>
                    <div class="category-details">
                        {format_category("Financial Risks", risk_details["financial_risks"])}
                    </div>
                </div>

                <!-- Visualization -->
                <div class="chart-container">
                    <h3>Risk Categories Chart</h3>
                    <div>{bar_chart}</div>
                </div>

                <div class="text-center mt-4 mb-5">
                    <a href="/reports" class="btn btn-primary">Back to Reports</a>
                </div>
            </div>
        </body>
        </html>
    """, report=report, timezone=timezone, local_timezone=local_timezone, created_at_local=created_at_local, stats=stats, bar_chart=bar_chart, risk_details=risk_details)

@app.route('/reports/delete/<int:report_id>', methods=['GET', 'POST'])
@login_required
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return "Unauthorized access", 403
    db.session.delete(report)
    db.session.commit()
    return redirect(url_for('reports'))

#Generate a downloadable PDF report
@app.route('/generate_report/<int:report_id>', methods=['GET'])
@login_required
def generate_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return "Unauthorized access", 403

    # Retrieve risk details
    risk_messages = report.risk_message.split("<br>")
    oversharing_posts = [msg for msg in risk_messages if "Potential oversharing" in msg]
    emotional_trigger_posts = [msg for msg in risk_messages if "Potential emotional trigger" in msg]
    personal_data_posts = [msg for msg in risk_messages if "Potential phone number" in msg or "Potential email address" in msg]
    financial_info_posts = [msg for msg in risk_messages if "Potential financial information" in msg]

    # Generate bar chart (same as in the view report section)
    categories = ['Oversharing', 'Emotional Triggers', 'Personal Data', 'Financial Risks']
    risk_counts = [
        len(oversharing_posts),
        len(emotional_trigger_posts),
        len(personal_data_posts),
        len(financial_info_posts),
    ]
    fig = go.Figure(data=[go.Bar(x=categories, y=risk_counts)])
    fig.update_layout(
        title="",
        xaxis_title="RiskCategory",
        yaxis_title="Number of Posts",
        template="plotly_white",
    )
    chart_path = f"/tmp/risk_breakdown_chart_{report_id}.png"
    fig.write_image(chart_path)

    # Generate HTML for PDF
    html_content = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                line-height: 1.4;
                font-size: 12px;
            }}
            h1 {{
                text-align: center;
                font-size: 18px;
                margin-bottom: 20px;
            }}
            h2 {{
                font-size: 16px;
                margin-top: 30px;
                margin-bottom: 15px;
                border-bottom: 1px solid #000;
            }}
            h3 {{
                font-size: 14px;
                margin-top: 25px;
                margin-bottom: 10px;
            }}
            .section {{
                margin-bottom: 40px;
            }}
            .post {{
                margin-bottom: 15px;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }}
            .chart {{
                text-align: center;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <h1>SMAT Analysis Report</h1>

        <div class="section">
            <h2>Profile Information</h2>
            <p><strong>Date Created:</strong> {report.created_at.strftime('%Y-%m-%d %H:%M')}</p>
            <p><strong>Risk Score:</strong> {report.risk_score:.2f}</p>
        </div>

        <div class="section">
            <h2>Risk Categories</h2>
            <p><strong>Oversharing:</strong> {len(oversharing_posts)} posts</p>
            <p><strong>Emotional Triggers:</strong> {len(emotional_trigger_posts)} posts</p>
            <p><strong>Personal Data:</strong> {len(personal_data_posts)} posts</p>
            <p><strong>Financial Risks:</strong> {len(financial_info_posts)} posts</p>
        </div>

        <div class="section">
            <h2>Detailed Posts</h2>

            <h3>Oversharing Posts</h3>
            {"".join(f"<div class='post'>{post}</div>" for post in oversharing_posts) or "<p>No oversharing posts detected.</p>"}

            <h3>Emotional Trigger Posts</h3>
            {"".join(f"<div class='post'>{post}</div>" for post in emotional_trigger_posts) or "<p>No emotional trigger posts detected.</p>"}

            <h3>Personal Data</h3>
            {"".join(f"<div class='post'>{post}</div>" for post in personal_data_posts) or "<p>No personal data posts detected.</p>"}

            <h3>Financial Risks</h3>
            {"".join(f"<div class='post'>{post}</div>" for post in financial_info_posts) or "<p>No financial risk posts detected.</p>"}
        </div>
        <div class="chart">
            <h2>Risk Breakdown Chart</h2>
            <img src="file://{chart_path}" alt="Risk Breakdown Chart" width="600">
        </div>
    </body>
    </html>
    """

    # Convert HTML to PDF
    pdf = HTML(string=html_content).write_pdf()

    # Serve the PDF as a downloadable file
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=smat_report_{report_id}.pdf'
    return response



# Logout route
@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))


@app.route('/suggestions')
@login_required
def suggestions():
    # Retrieve the latest risk message and score for personalized suggestions
    latest_report = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).first()

    # General suggestions
    general_tips = [
        "Avoid oversharing personal details such as location or sensitive information.",
        "Use strong and unique passwords for your social media accounts.",
        "Enable two-factor authentication wherever possible.",
        "Be cautious of phishing messages or suspicious links.",
        "Regularly review your privacy settings on social media platforms.",
    ]

    # Personalized suggestions based on risk level
    personalized_tips = []
    if latest_report:
        if latest_report.risk_score >= 2:
            personalized_tips.append("Your risk level is HIGH. Avoid sharing sensitive details like phone numbers and emails in your posts.")
        elif 1 <= latest_report.risk_score < 2:
            personalized_tips.append("Your risk level is MEDIUM. Be mindful of emotional content that could make you susceptible to manipulation.")
        else:
            personalized_tips.append("Your risk level is LOW. Keep maintaining good social media practices!")

    # Render the suggestions page
    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Suggestions - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <a class="navbar-brand" href="/">SMAT</a>
                <div class="collapse navbar-collapse">
                    <ul class="navbar-nav ml-auto">
                        <li class="nav-item">
                            <a class="nav-link" href="/profile">Profile</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/reports">Reports</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/suggestions">Suggestions</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/logout">Logout</a>
                        </li>
                    </ul>
                </div>
            </nav>
            <div class="container mt-5">
                <h2>Suggestions for Reducing Risk</h2>
                <h4 class="mt-4">General Tips</h4>
                <ul class="list-group">
                    {% for tip in general_tips %}
                        <li class="list-group-item">{{ tip }}</li>
                    {% endfor %}
                </ul>
                {% if personalized_tips %}
                    <h4 class="mt-4">Personalized Suggestions</h4>
                    <ul class="list-group">
                        {% for tip in personalized_tips %}
                            <li class="list-group-item text-warning">{{ tip }}</li>
                        {% endfor %}
                    </ul>
                {% endif %}
                <a href="/profile" class="btn btn-secondary mt-3">Back to Profile</a>
            </div>
        </body>
        </html>
    """, general_tips=general_tips, personalized_tips=personalized_tips)


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        # Delete all reports associated with the user
        reports = Report.query.filter_by(user_id=current_user.id).all()
        for report in reports:
            db.session.delete(report)
        
        # Delete the user account
        user = User.query.get(current_user.id)
        db.session.delete(user)
        db.session.commit()
        
        # Logout and redirect to home page
        logout_user()
        session.clear()
        return redirect(url_for('index'))

    # Confirmation page
    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Delete Account - SMAT</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container mt-5">
                <h2>Delete Your Account</h2>
                <p class="text-danger">Warning: This action is irreversible and will delete all your data.</p>
                <form method="POST">
                    <button type="submit" class="btn btn-danger">Confirm Delete</button>
                    <a href="/profile" class="btn btn-secondary">Cancel</a>
                </form>
            </div>
        </body>
        </html>
    """)

if __name__ == '__main__':
    app.run(debug=True)
