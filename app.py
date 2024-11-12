from flask import Flask, redirect, request, url_for, session, render_template_string, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from textblob import TextBlob
import re
import plotly.graph_objs as go
import plotly.io as pio
import plotly.express as px
from weasyprint import HTML
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

# Logout route
@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))

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
        'fields': 'id,name,email,picture,birthday,location,posts',
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

    # Dynamic weighting for sensitive info frequency
    phone_number_count = 0
    email_count = 0
    negative_sentiment_count = 0

    # Analyze posts
    posts_html = "<ul>"
    sentiments = []
    post_messages = []
    phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    emotional_triggers = ['angry', 'sad', 'frustrated', 'depressed', 'upset', 'anxious']
    oversharing_words = ['birthday', 'vacation', 'family', 'wedding', 'graduation', 'party']

    for post in posts_data:
        message = post.get('message', 'No message')

        # Sentiment analysis
        blob = TextBlob(message)
        sentiment = blob.sentiment.polarity
        sentiments.append(sentiment)
        post_messages.append(message[:50])  # Shortened for display

        # Check for emotional trigger words
        if any(trigger in message.lower() for trigger in emotional_triggers):
            emotional_risk += 3
            risk_message += f"Emotional trigger found in post: {message}<br>"

        # Check for oversharing content
        if any(word in message.lower() for word in oversharing_words):
            personal_data_risk += 2
            risk_message += f"Potential oversharing found in post: {message}<br>"

        # Check for sensitive information
        if re.search(phone_pattern, message):
            phone_number_count += 1
            risk_message += f"Potential phone number found in post: {message}<br>"
        if re.search(email_pattern, message):
            email_count += 1
            risk_message += f"Potential email address found in post: {message}<br>"

        # Sentiment-based emotional risk calculation
        if sentiment < 0:
            negative_sentiment_count += 1
            if sentiment < -0.5:
                emotional_risk += 3  # Strong negative sentiment
            else:
                emotional_risk += 1  # Mild negative sentiment

        posts_html += f"<li class='list-group-item'>{message} (Sentiment score: {sentiment})</li>"

    posts_html += "</ul>"

    # Apply dynamic weights for frequency of sensitive info
    if phone_number_count > 1:
        financial_risk += phone_number_count * 5  # Multiple phone numbers
    elif phone_number_count == 1:
        financial_risk += 5

    if email_count > 1:
        financial_risk += email_count * 3  # Multiple email occurrences
    elif email_count == 1:
        financial_risk += 3  # Single email occurrence

    # Final risk score based on categorized risks
    total_risk_score = personal_data_risk + financial_risk + emotional_risk

    # Store total_risk_score and risk_message in session for report generation
    session['risk_score'] = total_risk_score
    session['risk_message'] = risk_message

    # Create Sentiment Bar Chart
    fig = go.Figure([go.Bar(x=post_messages, y=sentiments, marker_color='rgb(55, 83, 109)')])
    fig.update_layout(
        title='Sentiment Analysis of Recent Posts',
        xaxis_title='Post (Shortened)',
        yaxis_title='Sentiment Score (-1 to 1)',
        yaxis=dict(range=[-1, 1]),
        template='plotly_white'
    )
    sentiment_chart = pio.to_html(fig, full_html=False)  # Convert plotly figure to HTML

    # Create Pie chart for risk breakdown
    risk_factors = ['Emotional Risk', 'Personal Data Risk', 'Financial Risk']
    risk_values = [emotional_risk, personal_data_risk, financial_risk]

    fig_pie = px.pie(values=risk_values, names=risk_factors, title='Risk Breakdown')
    risk_pie_chart = pio.to_html(fig_pie, full_html=False)  # Convert plotly figure to HTML

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
                            <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                        </li>
                    </ul>
                </div>
            </nav>
            <div class="container mt-5">
                <h2>Profile Information</h2>
                <img src='{profile_data['picture']['data']['url']}' style='border-radius: 50%; width: 100px;'><br>
                <strong>Name:</strong> {profile_data['name']}<br>
                <strong>Email:</strong> {profile_data.get('email', 'No email')}<br>
                <strong>Birthday:</strong> {profile_data.get('birthday', 'No birthday')}<br>
                <strong>Location:</strong> {profile_data.get('location', {}).get('name', 'No location')}<br>

                <h3 class="mt-4">Recent Posts</h3>
                {posts_html}

                <h3>Sentiment Analysis Chart</h3>
                <div>{sentiment_chart}</div>

                <h3>Risk Breakdown Chart</h3>
                <div>{risk_pie_chart}</div>

                <h3>Risk Assessment</h3>
                <div class="alert {'alert-danger' if total_risk_score >= 5 else 'alert-success' if total_risk_score <= 2 else 'alert-warning'}">
                    {risk_message}
                </div>
                <a href="/generate_report" class="btn btn-primary mt-3">Download Report</a>
            </div>
        </body>
        </html>
    """)

# Step 5: Generate a downloadable PDF report
@app.route('/generate_report')
@login_required
def generate_report():
    access_token = session.get('access_token')
    profile_response = requests.get(FB_API_URL, params={
        'fields': 'id,name,email,picture,birthday,location,posts',
        'access_token': access_token
    })
    profile_data = profile_response.json()

    # Retrieve risk_score and risk_message from the session
    risk_score = session.get('risk_score', 'No score available')
    risk_message = session.get('risk_message', 'No risk assessment available')
    
    # Render the HTML content for the PDF
    html_content = f"""
    <h1>SMAT Analysis Report</h1>
    <h2>Profile Information</h2>
    <strong>Name:</strong> {profile_data['name']}<br>
    <strong>Email:</strong> {profile_data.get('email', 'No email')}<br>
    <h3>Risk Score:</h3>
    {risk_score}
    <h3>Risk Breakdown:</h3>
    {risk_message}
    """

    # Convert HTML to PDF
    pdf = HTML(string=html_content).write_pdf()

    # Serve the PDF as a downloadable file
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=smat_report.pdf'
    return response

if __name__ == '__main__':
    app.run(debug=True)
