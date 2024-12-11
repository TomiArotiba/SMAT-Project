from flask import Blueprint, redirect, request, url_for, session, render_template, make_response
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from tzlocal import get_localzone
from weasyprint import HTML
from plotly.subplots import make_subplots
import plotly.graph_objs as go
import plotly.io as pio
import numpy as np
import pandas as pd
import joblib
import requests
from datetime import timezone
import re
from .models import db, User, Report
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

#Load the trained Random Forest model
rf_model = joblib.load("random_forest_model.pkl")

#Create a Blueprint
main = Blueprint('main', __name__)

#Facebook OAuth configuration
FB_CLIENT_ID = '285793798673387'
FB_CLIENT_SECRET = 'afe12d73a976d18bb941012549d20243'
FB_REDIRECT_URI = 'http://localhost:5000/facebook/callback'
FB_AUTH_URL = 'https://www.facebook.com/dialog/oauth'
FB_TOKEN_URL = 'https://graph.facebook.com/v12.0/oauth/access_token'
FB_API_URL = 'https://graph.facebook.com/v12.0/me'


@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    else:
        return render_template('index.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        #Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            return "Email already registered"

        new_user = User(email=email, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('main.login'))

    return render_template('register.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return "Invalid credentials"

        login_user(user)
        return redirect(url_for('main.login_facebook'))

    return render_template('login.html')


@main.route('/login_facebook')
def login_facebook():
    return redirect(f"{FB_AUTH_URL}?client_id={FB_CLIENT_ID}&redirect_uri={FB_REDIRECT_URI}&scope=email,public_profile,user_birthday,user_location,user_posts")


@main.route('/facebook/callback')
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
    return redirect(url_for('main.profile'))


@main.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/profile', methods=['GET'])
@login_required
def profile():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('main.login_facebook'))

    #Fetch profile data using Facebook API
    profile_response = requests.get(FB_API_URL, params={
        'fields': 'id,name,email,picture,birthday,location,posts.limit(100)',
        'access_token': access_token
    })

    #Handle errors in API response
    if 'error' in profile_response.json():
        return render_template('profile.html', profile_data=None, error="Unable to fetch profile data. Check your privacy settings.")

    profile_data = profile_response.json()
    
    #Check for profiles with no posts
    posts_data = profile_data.get('posts', {}).get('data', [])
    total_posts = len(posts_data)

    if not posts_data:
        return render_template_string(f"""
            <h2>Profile Information</h2>
            <strong>Name:</strong> {profile_data['name']}<br>
            <strong>Email:</strong> {profile_data.get('email', 'No email')}<br>
            <p>No posts available for analysis.</p>
            <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        """)

    #Initialize risk categories
    personal_data_risk = 0
    financial_risk = 0
    emotional_risk = 0
    risk_message = ""

    #Lists for categorization
    oversharing_posts = []
    emotional_trigger_posts = []
    personal_data_posts = []
    financial_info_posts = []

    #Initialize VADER sentiment analyzer
    analyzer = SentimentIntensityAnalyzer()
    sentiments = []

    #Fetch posts and perform analysis
    post_messages = []
    oversharing_posts = []
    emotional_trigger_posts = []
    personal_data_posts = []
    financial_info_posts = []


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

    #Initialize counters
    num_sensitive_info = 0 
    num_emotional_triggers = 0  
    num_oversharing = 0  
    
    for post in posts_data:
        message = post.get('message', '').strip()

        if not message or message == "No message":
            continue

        #Sentiment analysis with VADER
        sentiment_score = analyzer.polarity_scores(message)['compound']
        
        if sentiment_score != 0: #remove posts with sentiment score 0
            sentiments.append(sentiment_score)
            post_messages.append({'message':message, 'sentiment_score': sentiment_score})
        
            if any(trigger in message.lower() for trigger in emotional_triggers):
                emotional_risk += 1
                num_emotional_triggers += 1
                risk_message += f"Potential emotional trigger found in post: {message}<br>"
                emotional_trigger_posts.append(message)

            if any(word in message.lower() for word in oversharing_words):
                personal_data_risk += 1
                num_oversharing += 1
                risk_message += f"Potential oversharing found in post: {message}<br>"
                oversharing_posts.append(message)

            if re.search(phone_pattern, message):
                personal_data_risk += 1
                num_sensitive_info += 1
                risk_message += f"Potential phone number found in post: {message}<br>"
                personal_data_posts.append(message)

            if re.search(email_pattern, message):
                personal_data_risk += 1
                num_sensitive_info += 1
                risk_message += f"Potential email address found in post: {message}<br>"
                personal_data_posts.append(message)

            if any(finance in message.lower() for finance in financial_keywords):
                financial_risk += 3 
                num_sensitive_info += 1
                risk_message += f"Potential financial information found in post: {message}<br>"
                financial_info_posts.append(message)

            #Adjust risk based on sentiment score  
            if sentiment_score <= -0.5:
                emotional_risk += 3  #Strong negative sentiment
            elif sentiment_score < 0:
                emotional_risk += 1  #Mild negative sentiment

    #Calculate avg_sentiment
    avg_sentiment = np.mean(sentiments) if sentiments else 0

    #Prepare features for the Random Forest model
    feature_names = ['avg_sentiment', 'num_sensitive_info', 'num_emotional_triggers', 'num_oversharing']
    features = pd.DataFrame([[avg_sentiment, num_sensitive_info, num_emotional_triggers, num_oversharing]], columns=feature_names)
    
    #Predict risk using the model
    predicted_risk = rf_model.predict(features)[0]

    #Combine model prediction with rule-based risks and define weights for risk categories
    weights = {'emotional': 0.2, 'personal_data': 0.4, 'financial': 0.4}

    # Weighted risk score
    weighted_heuristic_score = (
        weights['emotional'] * emotional_risk +
        weights['personal_data'] * personal_data_risk +
        weights['financial'] * financial_risk
    )

    #Combine rule-based and model predictions
    final_risk_score = 0.6 * predicted_risk + 0.4 * (weighted_heuristic_score / 10)  #Normalize heuristic score

    #Update risk message and display for testing.
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

    #Update session storage for PDF report
    session['profile_name'] = profile_data['name']
    session['profile_email'] = profile_data.get('email', 'No email')
    session['profile_birthday'] = profile_data.get('birthday', 'No birthday')
    session['profile_location'] = profile_data.get('location', {}).get('name', 'No location')                
    session['risk_score'] = float(final_risk_score)
    session['risk_message'] = risk_message
    session['risk_level'] = risk_level
    session['num_oversharing'] = num_oversharing
    session['num_emotional_triggers'] = num_emotional_triggers
    session['num_sensitive_info'] = num_sensitive_info
    session['num_financial_info'] = len(financial_info_posts)


    #Save report to the database
    new_report = Report(
        user_id=current_user.id,
        risk_score=final_risk_score,
        risk_message=risk_message,
        risk_level=risk_level
    )
    db.session.add(new_report)
    db.session.commit()
    
    #Fetch the latest report for the user
    latest_report = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).first()
    return render_template(
        'profile.html',
        profile_data=profile_data,
        post_messages=post_messages,
        risk_level=risk_level,
        oversharing_posts=oversharing_posts,
        emotional_trigger_posts=emotional_trigger_posts,
        personal_data_posts=personal_data_posts,
        financial_info_posts=financial_info_posts,
        latest_report=latest_report
    )


@main.route('/reports')
@login_required
def reports():
    user_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all()

    #Get the local timezone dynamically
    local_timezone = get_localzone()

    #Prepare data for graph
    report_dates = [
        report.created_at.replace(tzinfo=timezone.utc).astimezone(local_timezone) 
        for report in user_reports
    ]
    risk_scores = [report.risk_score for report in user_reports]

    #Format the dates for graph display
    formatted_dates = [date.strftime('%Y-%m-%d %H:%M') for date in report_dates]

    #Create a scatter plot using Plotly
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
    return render_template('reports.html', user_reports=user_reports, trend_chart=trend_chart, local_timezone=local_timezone, timezone=timezone)


@main.route('/reports/<int:report_id>')
@login_required
def view_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return "Unauthorized access", 403
    
    #Convert to local timezone
    local_timezone = get_localzone()
    created_at_local = report.created_at.replace(tzinfo=timezone.utc).astimezone(local_timezone).strftime('%Y-%m-%d %H:%M')

    #Extract statistics
    risk_messages = report.risk_message.split("<br>")
    risk_level = report.risk_level
    risk_score = report.risk_score

    stats = {
        "oversharing": sum("Potential oversharing" in msg for msg in risk_messages),
        "emotional_triggers": sum("Potential emotional trigger" in msg for msg in risk_messages),
        "personal_data": sum("Potential phone number" in msg or "Potential email address" in msg for msg in risk_messages),
        "financial_risks": sum("Potential financial information" in msg for msg in risk_messages),
    }

    #Separate posts by category
    risk_details = {
        "oversharing": [msg for msg in risk_messages if "Potential oversharing" in msg],
        "emotional_triggers": [msg for msg in risk_messages if "Potential emotional trigger" in msg],
        "personal_data": [msg for msg in risk_messages if "Potential phone number" in msg or "Potential email address" in msg],
        "financial_risks": [msg for msg in risk_messages if "Potential financial information" in msg],
    }


    #Visualization - Bar Chart
    categories = ["Oversharing", "Emotional Triggers", "Personal Data", "Financial Risks"]
    risk_counts = [stats["oversharing"], stats["emotional_triggers"], stats["personal_data"], stats["financial_risks"]]


    bar_fig = go.Figure([go.Bar(x=categories, y=risk_counts, marker=dict(color='#007bff'))])
    bar_fig.update_layout(
        title="",
        xaxis_title="Risk Category",
        yaxis_title="Count",
        template="plotly_white"
    )
    bar_chart = pio.to_html(bar_fig, full_html=False)

    return render_template('view_report.html',report=report, timezone=timezone, local_timezone=local_timezone, created_at_local=created_at_local, stats=stats, bar_chart=bar_chart, risk_details=risk_details, risk_level=risk_level, risk_score=risk_score)


@main.route('/reports/delete/<int:report_id>', methods=['GET', 'POST'])
@login_required
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return "Unauthorized access", 403
    db.session.delete(report)
    db.session.commit()
    return redirect(url_for('main.reports'))


@main.route('/generate_report/<int:report_id>', methods=['GET'])
@login_required
def generate_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        return "Unauthorized access", 403

    #Retrieve profile details from session
    profile_name = session.get('profile_name')
    profile_email = session.get('profile_email')
    profile_birthday = session.get('profile_birthday')
    profile_location = session.get('profile_location')
    risk_level = session.get('risk_level')

    #If session data is missing, fetch from Facebook API
    if not profile_name or not profile_email or not profile_birthday or not profile_location:
        access_token = session.get('access_token')
        profile_response = requests.get(FB_API_URL, params={
            'fields': 'id,name,email,birthday,location',
            'access_token': access_token
        })
        profile_data = profile_response.json()
        profile_name = profile_data.get('name', 'Not Available')
        profile_email = profile_data.get('email', 'Not Available')
        profile_birthday = profile_data.get('birthday', 'Not Available')
        profile_location = profile_data.get('location', {}).get('name', 'Not Available')

    #Retrieve risk details
    risk_messages = report.risk_message.split("<br>")
    oversharing_posts = [msg for msg in risk_messages if "Potential oversharing" in msg]
    emotional_trigger_posts = [msg for msg in risk_messages if "Potential emotional trigger" in msg]
    personal_data_posts = [msg for msg in risk_messages if "Potential phone number" in msg or "Potential email address" in msg]
    financial_info_posts = [msg for msg in risk_messages if "Potential financial information" in msg]

    #Generate bar chart (same as in the view report section)
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
        xaxis_title="Risk Category",
        yaxis_title="Number of Posts",
        template="plotly_white",
    )
    chart_path = f"/tmp/risk_breakdown_chart_{report_id}.png"
    fig.write_image(chart_path)

    #Generate HTML content for the PDF
    html_content = render_template('pdf_template.html', 
        profile_name=profile_name,
        profile_email=profile_email,
        profile_birthday=profile_birthday,
        profile_location=profile_location,
        risk_level=risk_level,
        report=report,
        oversharing_posts=oversharing_posts,
        emotional_trigger_posts=emotional_trigger_posts,
        personal_data_posts=personal_data_posts,
        financial_info_posts=financial_info_posts,
        chart_path=chart_path
    )

    #Convert HTML to PDF
    pdf = HTML(string=html_content).write_pdf()

    #Serve the PDF as a downloadable file
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=smat_report_{report_id}.pdf'
    return response

@main.route('/suggestions')
@login_required
def suggestions():
    #Retrieve the latest risk message and score for personalized suggestions
    latest_report = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).first()

    #General suggestions grouped by category
    general_tips = {
        "Privacy Settings": [
            "Regularly review your privacy settings on social media platforms.",
            "Limit who can see your posts and profile information.",
            "Avoid sharing your location in real-time."
        ],
        "Account Security": [
            "Use strong and unique passwords for your social media accounts.",
            "Enable two-factor authentication wherever possible.",
            "Be cautious of phishing messages or suspicious links."
        ],
        "Content Sharing": [
            "Think twice before sharing personal details such as birthdays, vacations, or sensitive information.",
            "Avoid posting financial details or personal data like phone numbers or email addresses.",
            "Refrain from engaging in emotionally charged posts or sharing emotional triggers."
        ]
    }

    #Personalized suggestions and additional recommendations
    personalized_suggestions = ""
    risk_level_color = "black"  #Default for low risk
    if latest_report:
        risk_score = latest_report.risk_score

        if risk_score >= 2:  #HIGH Risk
            risk_level_color = "red"
            personalized_suggestions = """
                <p><strong>Your risk level is <span style='color: red;'>HIGH</span>.</strong> Immediate action is recommended to reduce your exposure.</p>
                <p>Recommendations:</p>
                <ul>
                    <li>Remove or edit posts containing sensitive information, such as financial details, phone numbers, or email addresses.</li>
                    <li>Reduce oversharing by limiting posts about personal events like birthdays, vacations, or work locations.</li>
                    <li>Avoid posting emotionally charged content that could make you vulnerable to manipulation.</li>
                    <li>Regularly monitor your account for suspicious activity or unauthorized access.</li>
                </ul>
            """
        elif 1 <= risk_score < 2:  #MEDIUM Risk
            risk_level_color = "darkgoldenrod"
            personalized_suggestions = """
                <p><strong>Your risk level is <span style='color: darkgoldenrod;'>MEDIUM</span></strong>.</p>
                <p>Some improvements in your social media behavior are recommended.</p>
                <p>Recommendations:</p>
                <ul>
                    <li>Review your recent posts for any oversharing or emotional content and remove them if necessary.</li>
                    <li>Strengthen your account security by enabling two-factor authentication and updating passwords.</li>
                    <li>Be cautious of unsolicited messages or links that could be phishing attempts.</li>
                    <li>Limit sharing posts about your location or daily activities in real-time.</li>
                </ul>
            """
        else:  #LOW Risk
            risk_level_color = "black"
            personalized_suggestions = """
                <p><strong>Your risk level is <span style='color: black;'>LOW</span>.</strong> Keep up the good practices!</p>
                <p>Recommendations:</p>
                <ul>
                    <li>Continue to monitor your posts and avoid sharing sensitive information.</li>
                    <li>Stay cautious about any suspicious messages or links.</li>
                    <li>Review your privacy settings periodically to ensure they align with best practices.</li>
                </ul>
            """
    return render_template('suggestions.html', general_tips=general_tips, personalized_suggestions=personalized_suggestions)


@main.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        #Delete all reports associated with the user
        reports = Report.query.filter_by(user_id=current_user.id).all()
        for report in reports:
            db.session.delete(report)

        #Delete the user account
        user = User.query.get(current_user.id)
        db.session.delete(user)
        db.session.commit()

        logout_user()
        session.clear()
        return redirect(url_for('main.index'))

    return render_template('delete_account.html')
