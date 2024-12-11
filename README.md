
# **SMAT: Social Media Analysis Tool**

SMAT is a Flask-based application designed to analyze social media profiles and assess their susceptibility to social engineering attacks. It offers features like sentiment analysis, risk detection, and suggestions for reducing risk.

---

## **Features**
- **User Registration and Login**: Secure user authentication with Flask-Login.
- **Facebook Integration**: OAuth-based login to fetch social media profile data.
- **Profile Analysis**: Analyze recent posts for potential risks, including oversharing, emotional triggers, and sensitive information.
- **Risk Reports**: Generate detailed reports with risk scores and visualizations.
- **Suggestions**: Personalized suggestions for reducing risks based on analysis.
- **Account Management**: View reports, delete reports, and delete user accounts.
- **Export Reports**: Download reports as PDFs with charts and risk breakdowns.

---

## **Prerequisites**
Before running the application, ensure the following are installed:
- Python 3.8 or higher
- Flask and required Python libraries (listed in `requirements.txt`)
- A Facebook Developer account with an app configured for OAuth login

---

## **Installation**
1. **Clone the Repository**:
   ```bash
   https://github.com/TomiArotiba/SMAT-Project
   cd smat
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Linux/Mac
   venv\Scripts\activate     # For Windows
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure the Application**:
   - Open `routes.py` or `.env` file (if using one).
   - Add your **Facebook App credentials**:
     ```python
     FB_CLIENT_ID = 'your-facebook-client-id'
     FB_CLIENT_SECRET = 'your-facebook-client-secret'
     FB_REDIRECT_URI = 'http://localhost:5000/facebook/callback'
     ```

5. **Set Up the Database**:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

6. **Train and Save the Risk Model**:
   Run `risk_model.py` to train the random forest model and save it as `random_forest_model.pkl`.

   ```bash
   python risk_model.py
   ```

7. **Run the Application**:
   ```bash
   flask run
   ```

   The app will be accessible at [http://localhost:5000](http://localhost:5000).

---

## **Usage Instructions**
1. **Register an Account**:
   - Visit the homepage and click on "Register."
   - Enter your email and password.

2. **Log In**:
   - After registration, log in with your credentials.
   - Connect your Facebook account for analysis.

3. **Analyze Your Profile**:
   - The app will fetch your recent posts and display potential risks in categories like oversharing, emotional triggers, and sensitive information.
   - A risk score and risk level will be calculated.

4. **View Reports**:
   - Access all generated reports in the "Reports" section.
   - View details, download as PDFs, or delete individual reports.

5. **Get Suggestions**:
   - Visit the "Suggestions" section for personalized advice on reducing risks.

6. **Account Management**:
   - Delete your account and all associated reports from the "Delete Account" option.

---

## **Project Structure**
```
smat/
├── instance/
│   ├── users.db                  # SQLite database
├── app/      
│   ├──templates/                 # HTML templates for rendering pages
│       ├── base.html             # Base layout template
│       ├── index.html            # Home page
│       ├── profile.html          # Profile analysis page
│       ├── reports.html          # Reports list page
│       ├── view_report.html      # Detailed report view
│       ├── suggestions.html      # Suggestions page
│       ├── delete_account.html   # Delete account confirmation
│   ├── __init__.py               # Flask app factory
│   ├── routes.py                 # All application routes
│   ├── models.py                 # Database models
├── run.py                        # flask run
├── risk_model.py                 # Machine learning model training script
├── random_forest_model.pkl       # Trained Random Forest model
├── requirements.txt              # Python dependencies
├── README.md                     # Instructions and project details
├── requirements.txt              # Python dependencies
├── README.md                     # Project documentation
├── docker-compose.yml            # Docker Compose configuration
├── Dockerfile                    # Docker image instructions
├── training_data.csv             # Training dataset for risk model
```

---

## **Technologies Used**
- **Backend**: Flask (Python)
- **Frontend**: Jinja2 Templates, Bootstrap
- **Database**: SQLite with Flask-SQLAlchemy
- **Machine Learning**: Random Forest Classifier
- **API Integration**: Facebook Graph API
- **PDF Generation**: WeasyPrint
- **Visualizations**: Plotly

---

## **Potential Enhancements**
- Add multi-language support.
- Expand analysis to include other social media platforms.
- Implement advanced ML models for better risk prediction.

---

## **Troubleshooting**
1. **Issue**: Facebook login fails.
   - **Solution**: Ensure the redirect URI matches the one configured in your Facebook Developer app.

2. **Issue**: Risk score displays as `None`.
   - **Solution**: Check if `random_forest_model.pkl` exists and is correctly trained.

3. **Issue**: Charts not showing in downloaded PDF.
   - **Solution**: Ensure the `orca` package or an alternative renderer is installed for Plotly.

4. **Issue**: `Session cookie too large`.
   - **Solution**: Reduce session data stored or configure server-side session storage.

---
