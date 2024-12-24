import time
import pandas as pd
from risk_model import best_rf_model  # Import your model

def test_model_training_performance():
    """Measure the time taken to train the risk model."""
    # Prepare mock training data
    data = pd.DataFrame({
        'avg_sentiment': [0.5, -0.3, 0.8, 0.2],
        'num_sensitive_info': [2, 1, 5, 3],
        'num_emotional_triggers': [1, 2, 0, 1],
        'num_oversharing': [3, 4, 1, 2],
        'risk_level': [1, 0, 2, 1]  # Target variable
    })

    start_time = time.time()
    best_rf_model.fit(data.drop('risk_level', axis=1), data['risk_level'])
    end_time = time.time()

    print(f"Model Training Time: {end_time - start_time:.2f} seconds")
    assert (end_time - start_time) < 5  # Example threshold
