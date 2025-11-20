# 🛡️ Phishing URL Detection System  
_A Real-Time Machine Learning Web Application for Detecting Malicious URLs_

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Backend-green.svg)
![XGBoost](https://img.shields.io/badge/Model-XGBoost-orange.svg)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

---

## 📌 Overview
The **Phishing URL Detection System** is a real-time web-based tool that identifies phishing URLs using Machine Learning. It extracts lexical, host-based, and content-based features, then classifies the URL using a trained **XGBoost** model.  
The system also includes **Explainable AI (XAI)** to highlight features that contributed to the prediction.

---

## ✨ Features
✅ **Real-time URL Analysis** — Extracts 57 features such as domain age, URL structure, HTML tags, and more  
✅ **Machine Learning Engine** — XGBoost model trained on 11k+ samples with ~94.6% accuracy  
✅ **Explainable AI (XAI)** — Shows which features influenced the model’s prediction  
✅ **Responsive UI** — Built with Tailwind CSS + Vanilla JavaScript  
✅ **RESTful API** — Flask backend with CORS enabled  

---

## 🛠️ Technology Stack

### **Frontend**
- HTML5  
- Tailwind CSS (CDN)  
- Lucide Icons  
- Vanilla JavaScript (Fetch API)

### **Backend**
- Python (Flask REST API)

### **Machine Learning**
- XGBoost  
- Scikit-learn  
- Pandas  
- NumPy  
- Joblib

### **Feature Extraction**
- BeautifulSoup4  
- python-whois  
- Requests / Urllib

---

## 📦 Prerequisites
Ensure the following are installed:

- **Python 3.8+**
- Any modern browser (Chrome, Firefox, Edge)
- Internet access (WHOIS lookups)

---

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone <repository-url>
cd phishing-detection-system

```

## 2️⃣ Install Dependencies
pip install flask flask-cors pandas numpy joblib scikit-learn xgboost python-whois beautifulsoup4 requests


✔️ Use python-whois, not whois

## 3️⃣ Add the Trained Model

Ensure xgboost_model_v2.joblib is inside the project root.
If missing, run the training notebook:

Phishing_Detector_Modeling.ipynb

## ▶️ Running the Application
### 1. Start the Backend Server
python pdApp.py


Backend runs on:
http://0.0.0.0:5000
Endpoint: /scan

### 2. Launch the Frontend

Open index.html in your browser
(or serve using a simple HTTP server).

Frontend calls:
http://127.0.0.1:5000/scan

### 3. Perform a Scan

Enter a URL

Click Scan URL

View: Classification + Confidence Score + XAI Features

## 📊 Model & Dataset

- The ML workflow includes:

- Dataset Size: 89 raw columns

- Final Feature Count: 57 real-time extractable features

- Optimizer: Optuna (Best F1 Score: 0.9460)

- Model: XGBoost (balanced optimized hyperparameters)

### Feature Categories
#### 🔹 Lexical Features

- URL length

- Count of dots/hyphens

- IP address in URL

#### 🔹 Host-based Features

- Domain age

- Registration length (WHOIS)

#### 🔹 Content-based Features

- Login form presence

- Iframe usage

- Hyperlink ratios

- External favicon

## 📁 Project Structure
```
├── dataset_phishing.csv             # Raw dataset
├── Phishing_Detector_Modeling.ipynb # Notebook for model training
├── xgboost_model_v2.joblib          # Trained ML model
├── pdApp.py                         # Flask backend + feature extractor
├── index.html                       # Frontend UI
└── README.md                        # Documentation
```

## 🐞 Troubleshooting
### ❗ WHOIS Errors

Ensure port 43 is open; python-whois queries external WHOIS servers.

### ❗ CORS Issues

Flask is already configured using:

from flask_cors import CORS
CORS(app)

### ❗ Feature Mismatch

**When retraining, ensure:**

REALISTIC_FEATURES in pdApp.py matches the notebook used for training.

## 📜 License

This project is licensed under:

MIT License

## 🤝 Contributing

Pull requests are welcome!
For major changes, please open an issue first to discuss what you’d like to improve.

## ⭐ Acknowledgements

Developers & contributors

Open-source community

Dataset providers

## ❤️ Support the Project

If this project helped you, consider giving it a star ⭐ on GitHub!