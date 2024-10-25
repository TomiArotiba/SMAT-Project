from flask import Flask, redirect, request, url_for, session, render_template_string, make_response
import requests
from textblob import TextBlob
import re
import plotly.graph_objs as go
import plotly.io as pio
import plotly.express as px
from weasyprint import HTML

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Facebook OAuth endpoints and credentials
FB_CLIENT_ID = '285793798673387'
FB_CLIENT_SECRET = 'afe12d73a976d18bb941012549d20243'
FB_REDIRECT_URI = 'http://localhost:5000/facebook/callback'
FB_AUTH_URL = 'https://www.facebook.com/dialog/oauth'
FB_TOKEN_URL = 'https://graph.facebook.com/v12.0/oauth/access_token'
FB_API_URL = 'https://graph.facebook.com/v12.0/me'

# Home page with login/logout links
@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('profile'))
    else:
        return render_template_string("""
            <h1>Welcome to SMAT!</h1>
            <a href="{{ url_for('login') }}">Login with Facebook</a>
        """)

# Step 1: Redirect user to Facebook for authorization
@app.route('/login')
def login():
    return redirect(f"{FB_AUTH_URL}?client_id={FB_CLIENT_ID}&redirect_uri={FB_REDIRECT_URI}&scope=email,public_profile,user_birthday,user_location,user_posts")

# Step 2: Callback function to handle Facebook's response
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

# Step 3: Fetch user profile data with additional fields and analyze it
@app.route('/profile')
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))
    
    access_token = session.get('access_token')
    profile_response = requests.get(FB_API_URL, params={
        'fields': 'id,name,email,picture,birthday,location,posts',
        'access_token': access_token
    })
    
    # Error handling for private or restricted profiles
    if 'error' in profile_response.json():
        return render_template_string(f"""
            <p>Unable to retrieve data for this profile. Please check your privacy settings.</p>
            <a href="{{ url_for('logout') }}">Logout</a>
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
            <a href="{{ url_for('logout') }}">Logout</a>
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

        posts_html += f"<li>{message} (Sentiment score: {sentiment})</li>"

    posts_html += "</ul>"

    # Apply dynamic weights for frequency of sensitive info
    if phone_number_count > 1:
        financial_risk += phone_number_count * 5  # Multiple phone numbers
    elif phone_number_count == 1:
        financial_risk += 5  # Single phone number

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
        <style>
            body {{ font-family: Arial, sans-serif; }}
            h2, h3 {{ color: #2c3e50; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ background-color: #ecf0f1; margin: 10px 0; padding: 10px; border-radius: 5px; }}
            .risk-score {{ padding: 20px; background-color: #f39c12; color: white; border-radius: 5px; }}
            .risk-high {{ background-color: #e74c3c; }}
            .risk-low {{ background-color: #2ecc71; }}
        </style>
        <h2>Profile Information</h2>
        <img src='{profile_data['picture']['data']['url']}' style='border-radius: 50%; width: 100px;'><br>
        <strong>Name:</strong> {profile_data['name']}<br>
        <strong>Email:</strong> {profile_data.get('email', 'No email')}<br>
        <strong>Birthday:</strong> {profile_data.get('birthday', 'No birthday')}<br>
        <strong>Location:</strong> {profile_data.get('location', {}).get('name', 'No location')}<br>

        <h3>Recent Posts</h3>
        {posts_html}

        <h3>Sentiment Analysis Chart</h3>
        {sentiment_chart}

        <h3>Risk Breakdown Chart</h3>
        {risk_pie_chart}

        <h3>Risk Assessment</h3>
        <div class="risk-score {'risk-high' if total_risk_score >= 5 else 'risk-low' if total_risk_score <= 2 else ''}">
            {risk_message}
        </div>
        <br>
        <a href="/generate_report" class="btn btn-primary">Download Report</a>
        <br>
        <a href="/logout">Logout</a>
    """)

# Step 4: Logout and clear the session
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Step 5: Generate a downloadable PDF report
@app.route('/generate_report')
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
