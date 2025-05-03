import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' 

import warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', message='.*Trying to unpickle estimator.*')

import pandas as pd
import joblib
import numpy as np
import tensorflow as tf
import re
from utils import get_latest_csv

def preprocess_flow(flow_file):
    """
    Preprocess a flow file using the saved preprocessors
    Args:
        flow_file (str): Path to the flow CSV file
    Returns:
        numpy.ndarray: Preprocessed features ready for prediction
    """
    preprocessors = joblib.load('lib/preprocessors.pkl')
    
    df = pd.read_csv(flow_file)
    
    if df.empty:
        raise ValueError(f"Flow file {flow_file} is empty. No network traffic captured.")
        
    missing_cols = [col for col in preprocessors['dropped_cols'] if col in df.columns]
    if not missing_cols:
        raise ValueError(f"Flow file {flow_file} does not contain expected columns. Please check CICFlowMeter output.")
    
    df = df.drop(columns=preprocessors['dropped_cols'] + ['Label'], errors='ignore')
    
    if df.empty:
        raise ValueError("No data remains after preprocessing. Please check flow file format.")
    
    # Remove rows with infinity values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    
    if df.empty:
        raise ValueError("No data remains after removing infinite values.")
    
    # Handle extremely large values by clipping them to reasonable limits
    # Calculate percentile-based limits to avoid outlier influence
    upper_limits = df.quantile(0.99)
    lower_limits = df.quantile(0.01)
    
    # Clip values to within these limits
    df = df.clip(lower=lower_limits, upper=upper_limits, axis=1)
    
    X = preprocessors['imputer'].transform(df)
    X = preprocessors['constant_filter'].transform(X)
    X = preprocessors['scaler'].transform(X)
    X = preprocessors['selector'].transform(X)
    
    return X


def get_label_mapping():
    """
    Get the label mapping from preprocessors
    Returns:
        dict: Mapping of label indices to attack types
    """
    preprocessors = joblib.load('lib/preprocessors.pkl')
    return {v: k for k, v in preprocessors['label_mapping'].items()}


def predict_attack(X, model):
    """
    Get predictions using the deep learning model
    Args:
        model (keras): Trained deep learning model
        X (numpy.ndarray): Preprocessed features
    Returns:
        tuple: (predicted_label, prediction_probabilities)
    """     
    pred_probs = model.predict(X)
    pred_label = pred_probs.argmax(axis=1)
    
    return pred_label, pred_probs


if __name__ == "__main__":
    model = tf.keras.models.load_model('lib/deep_learning_model.h5')
    flow_file = ""
    
    if flow_file == "" or not os.path.exists(flow_file):
        flow_file = get_latest_csv("flows/")
        if flow_file is None:
            print("Error: No CSV files found in the flows directory!")
            exit(1)
        print(f"Using latest flow file: {flow_file}")
    else:
        print(f"Using default flow file: {flow_file}")
    
    print("Starting prediction test...")
    
    try:
        print("\nTesting preprocessing...")
        X = preprocess_flow(flow_file)
        print("Preprocessing successful!")
        print(f"Preprocessed data shape: {X.shape}")
        
        print("\nTesting label mapping...")
        label_mapping = get_label_mapping()
        print("Label mapping loaded successfully!")
        print("Available attack types:", list(label_mapping.values()))
        
        print("\nTesting prediction...")
        pred_label, pred_probs = predict_attack(X, model)
        
        unique_labels, counts = np.unique(pred_label, return_counts=True)
        total_flows = len(pred_label)
        
        print("\nPrediction Distribution:")
        for label, count in zip(unique_labels, counts):
            attack_type = label_mapping[label]
            percentage = (count / total_flows) * 100
            print(f"{attack_type}: {count} flows ({percentage:.2f}%)")
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure you have generated flow files first using capture.py")
    except Exception as e:
        print(f"Error during testing: {e}")