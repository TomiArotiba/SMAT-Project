import pandas as pd
from risk_model import best_rf_model

def test_risk_model_prediction():
    """Test Random Forest model prediction logic."""
    test_data = pd.DataFrame({
        'avg_sentiment': [0.5],
        'num_sensitive_info': [2],
        'num_emotional_triggers': [1],
        'num_oversharing': [3]
    })
    prediction = best_rf_model.predict(test_data)
    assert prediction in [0, 1, 2]  #Check for valid risk levels
