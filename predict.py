import pandas as pd
import joblib
import numpy as np
import tensorflow as tf

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
    df = df.drop(columns=preprocessors['dropped_cols'], errors='ignore')  
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
    print(preprocessors['label_mapping'])
    return {v: k for k, v in preprocessors['label_mapping'].items()}


def predict_attack(X):
    """
    Get predictions using the deep learning model
    Args:
        X (numpy.ndarray): Preprocessed features
    Returns:
        tuple: (predicted_label, prediction_probabilities)
    """
    model = tf.keras.models.load_model('lib/deep_learning_model.h5')

    pred_probs = model.predict(X)
    pred_label = pred_probs.argmax(axis=1)
    
    return pred_label, pred_probs