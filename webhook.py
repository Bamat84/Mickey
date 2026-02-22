from flask import Flask, request, abort
import hmac, hashlib, subprocess, os

app = Flask(__name__)
SECRET = os.environ.get("WEBHOOK_SECRET", "changeme")

@app.route("/webhook", methods=["POST"])
def webhook():
    sig = request.headers.get("X-Hub-Signature-256", "")
    body = request.get_data()
    expected = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        abort(403)
    subprocess.Popen(["/opt/mickey/deploy.sh"])
    return "OK", 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9000)
