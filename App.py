from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)


# =========================================================
# COMMON FUNCTIONS
# =========================================================

def get_status(score):
    if score >= 60:
        return "SUSPICIOUS"
    elif score >= 30:
        return "WARNING"
    return "LOW RISK"


def analyze_text(text):
    text = text.lower()

    score = 0
    reasons = []
    breakdown = []

    def add_risk(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)
        breakdown.append({
            "reason": reason,
            "points": points
        })

    # KYC
    if "kyc" in text:
        add_risk(25, "Possible KYC scam detected")

    # Account threat
    if any(x in text for x in [
        "account blocked",
        "account will be blocked",
        "account suspended",
        "account will be suspended"
    ]):
        add_risk(20, "Account blocking threat detected")

    # Links
    if any(x in text for x in [
        "click here",
        "click the link",
        "click this link",
        "http://",
        "https://"
    ]):
        add_risk(20, "Suspicious link instruction detected")

    # Bank
    if any(x in text for x in [
        "bank",
        "bank account",
        "upi",
        "credit card",
        "debit card"
    ]):
        add_risk(15, "Bank-related scam pattern detected")

    # OTP / credentials
    if any(x in text for x in [
        "otp",
        "password",
        "pin",
        "cvv"
    ]):
        add_risk(20, "Sensitive credential request detected")

    # Urgency
    if any(x in text for x in [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours"
    ]):
        add_risk(10, "Urgency or pressure tactic detected")

    # Prize
    if any(x in text for x in [
        "winner",
        "prize",
        "reward",
        "lottery"
    ]):
        add_risk(15, "Prize or reward scam pattern detected")

    # Payment
    if any(x in text for x in [
        "send money",
        "transfer money",
        "pay now",
        "make payment"
    ]):
        add_risk(20, "Suspicious payment request detected")

    score = min(score, 100)

    return {
        "status": get_status(score),
        "risk_score": score,
        "reasons": reasons,
        "breakdown": breakdown
    }


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return jsonify({
        "message": "FraudShield AI Backend is running!",
        "status": "online",
        "database": "Not required"
    })


# =========================================================
# MESSAGE DETECTION
# =========================================================

@app.route("/api/analyze-message", methods=["POST"])
def analyze_message():

    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        message = data.get("message", "").strip()

        if not message:
            return jsonify({"error": "Message is required"}), 400

        result = analyze_text(message)

        print("MESSAGE:", result)

        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 500


# =========================================================
# EMAIL DETECTION
# =========================================================

@app.route("/api/analyze-email", methods=["POST"])
def analyze_email():

    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        email = data.get("email", "").strip()

        if not email:
            return jsonify({"error": "Email content is required"}), 400

        result = analyze_text(email)

        print("EMAIL:", result)

        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 500


# =========================================================
# OTP / PHONE SCAM DETECTION
# =========================================================

@app.route("/api/analyze-phone", methods=["POST"])
def analyze_phone():

    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        phone_message = data.get("message", "").strip()

        if not phone_message:
            return jsonify({
                "error": "Phone message is required"
            }), 400

        result = analyze_text(phone_message)

        # Additional phone/OTP scam indicators
        text = phone_message.lower()

        extra_points = 0
        extra_reasons = []

        if any(x in text for x in [
            "share otp",
            "send otp",
            "tell me otp",
            "give me otp",
            "otp number"
        ]):
            extra_points += 25
            extra_reasons.append(
                "OTP sharing request detected"
            )

        if any(x in text for x in [
            "call this number",
            "call immediately",
            "contact this number",
            "customer care number"
        ]):
            extra_points += 10
            extra_reasons.append(
                "Suspicious phone-contact instruction detected"
            )

        result["risk_score"] = min(
            result["risk_score"] + extra_points,
            100
        )

        result["reasons"].extend(extra_reasons)

        for reason in extra_reasons:
            result["breakdown"].append({
                "reason": reason,
                "points": 25 if "OTP" in reason else 10
            })

        result["status"] = get_status(
            result["risk_score"]
        )

        print("PHONE:", result)

        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 500


# =========================================================
# URL DETECTION
# =========================================================

@app.route("/api/analyze-url", methods=["POST"])
def analyze_url():

    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "URL is required"}), 400

        text = url.lower()

        score = 0
        reasons = []
        breakdown = []

        def add_risk(points, reason):
            nonlocal score
            score += points
            reasons.append(reason)
            breakdown.append({
                "reason": reason,
                "points": points
            })

        if text.startswith("http://"):
            add_risk(
                20,
                "Website does not use secure HTTPS"
            )

        suspicious_words = [
            "login",
            "verify",
            "kyc",
            "bank",
            "account",
            "update",
            "secure",
            "reward",
            "prize",
            "password",
            "otp"
        ]

        found = sum(
            1 for word in suspicious_words
            if word in text
        )

        if found >= 2:
            add_risk(
                30,
                "Suspicious keywords detected in URL"
            )

        ip_pattern = r"https?://\d+\.\d+\.\d+\.\d+"

        if re.search(ip_pattern, url):
            add_risk(
                30,
                "URL uses an IP address instead of a domain name"
            )

        if "@" in url:
            add_risk(
                20,
                "Suspicious @ symbol detected in URL"
            )

        score = min(score, 100)

        result = {
            "status": get_status(score),
            "risk_score": score,
            "reasons": reasons,
            "breakdown": breakdown
        }

        print("URL:", result)

        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 500


# =========================================================
# TRANSACTION DETECTION
# =========================================================

@app.route("/api/analyze-transaction", methods=["POST"])
def analyze_transaction():

    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        amount = data.get("amount")

        try:
            amount = float(amount)
        except:
            return jsonify({
                "status": "WARNING",
                "risk_score": 50,
                "reasons": [
                    "Invalid transaction amount"
                ],
                "breakdown": [{
                    "reason": "Invalid transaction amount",
                    "points": 50
                }]
            })

        score = 0
        reasons = []
        breakdown = []

        if amount >= 100000:
            score = 80
            reasons.append(
                "Very high transaction amount detected"
            )
            breakdown.append({
                "reason": "Very high transaction amount detected",
                "points": 80
            })

        elif amount >= 50000:
            score = 60
            reasons.append(
                "High-value transaction detected"
            )
            breakdown.append({
                "reason": "High-value transaction detected",
                "points": 60
            })

        elif amount >= 20000:
            score = 30
            reasons.append(
                "Moderately high transaction detected"
            )
            breakdown.append({
                "reason": "Moderately high transaction detected",
                "points": 30
            })

        else:
            score = 5

        result = {
            "status": get_status(score),
            "risk_score": score,
            "reasons": reasons,
            "breakdown": breakdown
        }

        print("TRANSACTION:", result)

        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 500


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    return jsonify({
        "status": "healthy",
        "backend": "online",
        "database": "Not required",
        "features": [
            "Message Detection",
            "URL Detection",
            "Email Detection",
            "OTP Detection",
            "Phone Scam Detection",
            "Transaction Detection",
            "Explainable Fraud Score",
            "Real-Time High Risk Alert"
        ]
    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    print()
    print("==========================================")
    print("          FRAUDSHIELD AI BACKEND")
    print("==========================================")
    print("Message Detection       : ACTIVE")
    print("URL Detection           : ACTIVE")
    print("Email Detection         : ACTIVE")
    print("OTP Detection           : ACTIVE")
    print("Phone Scam Detection    : ACTIVE")
    print("Transaction Detection  : ACTIVE")
    print("Explainable Score       : ACTIVE")
    print("Real-Time Alerts        : ACTIVE")
    print("Dashboard               : ACTIVE")
    print("History                 : ACTIVE")
    print("MongoDB                 : NOT REQUIRED")
    print("==========================================")
    print("Server:")
    print("http://127.0.0.1:5000")
    print("==========================================")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
