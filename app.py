from flask import Flask, render_template
from sniffer import get_live_summary

app = Flask(__name__)

@app.route("/")
def home():
    summary = get_live_summary()
    summary["data_mode"] = "live"
    return render_template("index.html", summary=summary)

if __name__ == "__main__":
    app.run(debug=True)