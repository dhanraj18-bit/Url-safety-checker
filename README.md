# URL Safety Checker

The URL Safety Checker is a machine learning-based web application designed to identify potential phishing threats. Built with Python and Streamlit, it extracts lexical features from URLs and utilizes a trained Random Forest classifier to instantly evaluate and flag malicious websites, providing users with a simple, secure browsing safeguard.

## System Architecture

The application follows a straightforward, three-tier pipeline:

1. **User Interface (Front-End):** Built with Streamlit, providing a clean text input for users to submit URLs.
2. **Feature Extraction Engine (Middleware):** A custom Python class (`FeatureExtractor`) intercepts the raw URL text and uses regular expressions and parsing libraries to calculate 9 specific lexical features (e.g., URL length, use of IP addresses, subdomain count, presence of '@' symbols).
3. **Machine Learning Model (Back-End):** The extracted numerical features are passed to a pre-trained Scikit-Learn `RandomForestClassifier`. The model votes on the data and returns a prediction of `1` (Phishing) or `-1` (Safe), which is then rendered on the UI alongside the detected red flags.

## System Requirements

To run this project locally, your system must meet the following requirements:

* **Operating System:** Windows, macOS, or Linux
* **Python Version:** Python 3.8 or higher
* **Hardware:** Minimum 4GB RAM (for smooth model training and Streamlit execution)
* **Required Python Libraries:**
  * `streamlit`
  * `pandas`
  * `scikit-learn`
  * `joblib`
  * `numpy`
## Install Dependencies
Open terminal or command prompt, navigate to the project directory, and install the required libraries
```bash
pip install streamlit pandas scikit-learn joblib numpy
```
##Train the Model
Before running the web app, train the machine learning model on the lexical features. Run the training script:
```bash
python train_phishing_model.py
```
## Launch the Web Application
Once the model is saved, start the Streamlit server to interact with the front end:
```bash
streamlit run app.py
```
## output sample
<img width="1920" height="1020" alt="Screenshot 2026-03-30 235555" src="https://github.com/user-attachments/assets/a75c46e8-61ad-4c01-9dda-0623a15b75d7" />
