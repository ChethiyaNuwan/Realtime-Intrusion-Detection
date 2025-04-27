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


if __name__ == "__main__":
    test_flow_file = "flows/test_capture.pcap_Flow.csv"
    
    print("Starting prediction test...")
    
    try:
        print("\nTesting preprocessing...")
        X = preprocess_flow(test_flow_file)
        print("Preprocessing successful!")
        print(f"Preprocessed data shape: {X.shape}")
        
        print("\nTesting label mapping...")
        label_mapping = get_label_mapping()
        print("Label mapping loaded successfully!")
        print("Available attack types:", list(label_mapping.values()))
        
        print("\nTesting prediction...")
        pred_label, pred_probs = predict_attack(X)
        
        print("\nPrediction Results:")
        for i, (label, probs) in enumerate(zip(pred_label, pred_probs)):
            attack_type = label_mapping[label]
            confidence = probs[label] * 100
            print(f"Flow {i+1}: {attack_type} (Confidence: {confidence:.2f}%)")
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure you have generated flow files first using capture.py")
    except Exception as e:
        print(f"Error during testing: {e}")