import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

def train_model(csv_path):
    print(f"Loading dataset from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Error: Could not find '{csv_path}'. Please check the path.")
        return

    # 1. Filter for ONLY the features our front-end can extract
    features_to_keep = [
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
        'PrefixSuffix-', 'SubDomains', 'HTTPS', 'HTTPSDomainURL', 'class'
    ]
    
    # Keep only the columns that exist in our dataset and are in the list above
    df = df[[col for col in features_to_keep if col in df.columns]]
    print(f"Training on {len(df.columns)-1} lexical features instead of 30...")

    X = df.drop(columns=['class'])
    y = df['class']

    # 2. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Model Initialization and Training
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # 4. Model Evaluation
    print("Evaluating the model...")
    y_pred = model.predict(X_test)
    
    print(f"\n--- Results ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    # 5. Save the trained model and features
    joblib.dump(model, 'phishing_detection_model.pkl')
    joblib.dump(list(X.columns), 'model_features.pkl')
    print("New model saved successfully!")

if __name__ == "__main__":
    train_model('phishing.csv')