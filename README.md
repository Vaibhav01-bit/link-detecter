🛡️ PhishGuard – Advanced Phishing Detection System
PhishGuard is a web-based phishing detection tool that uses an ensemble of machine learning models to analyze URLs and detect phishing threats.

🚀 Features
Ensemble ML Models: Random Forest, Gradient Boosting, XGBoost (simulated predictions).

Real-Time URL Validation with instant feedback.

Feature Extraction: URL length, subdomains, HTTPS usage, suspicious keywords, domain age, IP detection, and more.

Risk Classification: Safe ✅, Suspicious ⚠️, Phishing 🚨.

Scan History stored in browser local storage.

Responsive & Animated UI.

📂 Files in This Project
backend.py – Backend logic & API simulation.

config.py – Backend configuration.

index.html – Main scanning interface.

index1.html – Login page template.

script.js – Frontend logic for detection & results display.

style.css – Styling & animations.

⚙️ How to Run
Clone this repo

bash
Copy
Edit
git clone https://github.com/your-username/phishguard.git
cd phishguard
Run Backend (optional for real API)

bash
Copy
Edit
pip install flask flask-cors
python backend.py
Run Frontend

Open index.html in a browser OR

Start a local server:

bash
Copy
Edit
python -m http.server 8000
Then visit: http://localhost:8000

📊 How It Works
User enters a URL.

System validates the URL format.

Extracts 30+ security-related features.

Predicts risk score using ensemble ML logic.

Displays classification & confidence with feature breakdown.

Saves result to scan history.

📜 License
MIT License – Free to use and modify.
