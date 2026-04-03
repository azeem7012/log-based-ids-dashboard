from flask import Flask, render_template, request
import json

app = Flask(__name__)

def load_alerts():
    try:
        with open("ids_report.json", "r") as f:
            return json.load(f)
    except:
        return []

@app.route("/")
def index():
    alerts = load_alerts()

    filter_type = request.args.get("type")

    if filter_type:
        alerts = [a for a in alerts if a["type"] == filter_type]

    total = len(alerts)
    brute = len([a for a in alerts if a["type"] == "BRUTE_FORCE"])
    port = len([a for a in alerts if a["type"] == "PORT_SCAN"])
    web = len([a for a in alerts if a["type"] == "EXCESSIVE_404"])
    suspicious = len([a for a in alerts if a["type"] == "SUSPICIOUS_LOGIN"])

    return render_template(
        "index.html",
        alerts=alerts,
        total=total,
        brute=brute,
        port=port,
        web=web,
        suspicious=suspicious
    )

if __name__ == "__main__":
    app.run(debug=True)
