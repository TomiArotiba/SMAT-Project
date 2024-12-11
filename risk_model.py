import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import cross_val_score
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

#Generate a dataset
num_samples = 1000
avg_sentiment = np.random.uniform(-1, 1, num_samples)
num_sensitive_info = np.random.randint(0, 10, num_samples)
num_emotional_triggers = np.random.randint(0, 5, num_samples)
num_oversharing = np.random.randint(0, 8, num_samples)

risk_label = [
    0 if s > 0.5 and si < 3 else  # Low risk
    2 if s < -0.5 or si >= 7 else  # High risk
    1  # Medium risk
    for s, si in zip(avg_sentiment, num_sensitive_info)
]

#Create a DataFrame
data = pd.DataFrame({
    'avg_sentiment': avg_sentiment,
    'num_sensitive_info': num_sensitive_info,
    'num_emotional_triggers': num_emotional_triggers,
    'num_oversharing': num_oversharing,
    'risk_label': risk_label
})

#Save the dataset
data.to_csv("training_data.csv", index=False)

#Load the dataset
data = pd.read_csv("training_data.csv")

#Features and target
X = data[['avg_sentiment', 'num_sensitive_info', 'num_emotional_triggers', 'num_oversharing']] #Independent variables
y = data['risk_label'] #Dependent variable

#Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

#Handle class imbalance using SMOTE
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

#Train Logistic Regression model (baseline)
logistic_model = LogisticRegression(max_iter=1000, random_state=42)
logistic_model.fit(X_train_resampled, y_train_resampled)

#Evaluate model
y_pred_logistic = logistic_model.predict(X_test)
print("Logistic Regression Model:")
print(classification_report(y_test, y_pred_logistic))
print(f"Accuracy: {accuracy_score(y_test, y_pred_logistic):.2f}")

#Train Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
rf_model.fit(X_train_resampled, y_train_resampled)

#Evaluate Random Forest model
y_pred_rf = rf_model.predict(X_test)
print("Initial Random Forest Model:")
print(classification_report(y_test, y_pred_rf))
print(f"Accuracy: {accuracy_score(y_test, y_pred_rf):.2f}")

#Hyperparameter tuning with Grid Search for Random Forest
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [5, 10, 15],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}
grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, scoring='accuracy', n_jobs=-1)
grid_search.fit(X_train_resampled, y_train_resampled)

#Best model and parameters
best_rf_model = grid_search.best_estimator_
print("Best Parameters:", grid_search.best_params_)

#Evaluate the best Random Forest model
y_pred_best_rf = best_rf_model.predict(X_test)
print("Optimized Random Forest Model:")
print(classification_report(y_test, y_pred_best_rf))
print(f"Accuracy: {accuracy_score(y_test, y_pred_best_rf):.2f}")

#Save the best model
joblib.dump(best_rf_model, "random_forest_model.pkl")

cv_scores = cross_val_score(best_rf_model, X, y, cv=5, scoring='accuracy')
print(f"Cross-Validation Accuracy: {cv_scores.mean():.2f} (+/- {cv_scores.std():.2f})")


#Precision, recall, and F1-score
print("Precision:", precision_score(y_test, y_pred_best_rf, average='weighted'))
print("Recall:", recall_score(y_test, y_pred_best_rf, average='weighted'))
print("F1-Score:", f1_score(y_test, y_pred_best_rf, average='weighted'))

#Confusion Matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred_best_rf))

#Identify misclassified samples
misclassified = X_test[y_test != y_pred_best_rf]
print("Misclassified Samples:", misclassified)

