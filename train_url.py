# train_url_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load CSV dataset
df = pd.read_csv("dataset/url_features.csv")

# Split features and labels
X = df.drop(columns=["label"])
y = df["label"]

# Split into train/test (optional)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a RandomForest model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save the model
joblib.dump(clf, "core/url_model.pkl")
print("✅ Model trained and saved as core/url_model.pkl")
