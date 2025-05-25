import os
import json
import threading
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, abort, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from io import BytesIO
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev")
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])
VALID_API_KEYS = {os.getenv("RECON_API_KEY")}

scan_results = {}
scan_lock = threading.Lock()

AMASS_BIN = r"C:\\Users\\Maman Sani Ibrahim\\Documents\\amass_Windows_amd64\\amass.exe"


def save_uploaded_file(file):
    if file and file.filename:
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        return path
    return None


class AmassRecon:
    def __init__(self, domain, output_dir="recon_output", wordlist_path=None, config_path=None):
        self.domain = domain
        self.start_time = datetime.now()
        self.timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(output_dir, f"{domain}_{self.timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        self.wordlist_path = wordlist_path
        self.config_path = config_path

    def run_command(self, command_args, outfile=None):
        print(f"🔧 Running Command: {' '.join(command_args)}")

        if outfile:
            full_path = os.path.join(self.output_dir, outfile)
            with open(full_path, "w") as f:
                result = subprocess.run(command_args, stdout=f, stderr=subprocess.PIPE)
            if result.returncode != 0:
                with open(full_path, "w") as ef:
                    ef.write(f"ERROR:\n{result.stderr.decode('utf-8')}")
            return full_path
        else:
            result = subprocess.run(command_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.decode("utf-8") if result.returncode == 0 else result.stderr.decode("utf-8")

    def intel(self):
        cmd = ["AMASS_BIN", "intel", "-whois", "-whois-historic", "-ip", "-org", "-d", self.domain]
        if self.config_path:
            cmd += ["-config", self.config_path]
        return self.run_command(cmd, f"{self.domain}_intel.txt")

    def passive_enum(self):
        cmd = ["AMASS_BIN", "enum", "-passive", "-json", "-d", self.domain]
        if self.config_path:
            cmd += ["-config", self.config_path]
        return self.run_command(cmd, f"{self.domain}_passive.json")

    def active_enum(self):
        cmd = ["AMASS_BIN", "enum", "-active", "-brute", "-json", "-d", self.domain]
        if self.wordlist_path:
            cmd += ["-w", self.wordlist_path]
        if self.config_path:
            cmd += ["-config", self.config_path]
        return self.run_command(cmd, f"{self.domain}_active.json")

    def parse_json_output(self, filename):
        subs = set()
        path = os.path.join(self.output_dir, filename)
        try:
            with open(path) as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        if "name" in obj:
                            subs.add(obj["name"])
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        return sorted(subs)

    def run_full_scan(self):
        self.intel()
        passive_path = self.passive_enum()
        active_path = self.active_enum()
        passive_subs = self.parse_json_output(os.path.basename(passive_path))
        active_subs = self.parse_json_output(os.path.basename(active_path))
        return passive_subs, active_subs


def execute_recon(domain, wordlist_path=None, config_path=None):
    recon = AmassRecon(domain, wordlist_path=wordlist_path, config_path=config_path)
    return recon.run_full_scan()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        wordlist_path = save_uploaded_file(request.files.get("wordlist_file"))
        config_path = save_uploaded_file(request.files.get("config_file"))

        try:
            passive, active = execute_recon(domain, wordlist_path, config_path)
        except Exception as e:
            return f"Scan failed: {str(e)}", 500

        session['domain'] = domain
        session['passive_subdomains'] = passive
        session['active_subdomains'] = active

        return render_template("results.html", domain=domain, passive=passive, active=active)

    return render_template("index.html")


@app.route("/api/recon", methods=["POST"])
@limiter.exempt
def api_recon():
    api_key = request.headers.get("X-API-KEY")
    if api_key not in VALID_API_KEYS:
        abort(403, "Forbidden: Invalid API Key")

    data = request.json
    domain = data.get("domain")
    wordlist = data.get("wordlist_file")
    config = data.get("config_file")

    try:
        passive, active = execute_recon(domain, wordlist, config)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"domain": domain, "passive": passive, "active": active})


@app.route("/download", methods=["GET"])
@limiter.exempt
def download():
    fmt = request.args.get('format', 'txt')
    domain = session.get('domain', 'results')
    passive = session.get('passive_subdomains', [])
    active = session.get('active_subdomains', [])

    if fmt == "json":
        content = json.dumps({"passive": passive, "active": active}, indent=2)
        mime, ext = "application/json", "json"
    elif fmt == "csv":
        content = "\n".join(["Subdomains:"] + passive + active)
        mime, ext = "text/csv", "csv"
    else:
        content = "\n".join(passive + active)
        mime, ext = "text/plain", "txt"

    buffer = BytesIO(content.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, mimetype=mime, as_attachment=True, download_name=f"{domain}_subdomains.{ext}")


def threaded_scan(domain):
    try:
        passive, active = execute_recon(domain)
        with scan_lock:
            scan_results[domain] = {
                "domain": domain,
                "passive": passive,
                "active": active,
                "subdomains": list(set(passive + active))
            }
    except Exception as e:
        print(f"Scan error for {domain}: {str(e)}")


@app.route("/async_scan", methods=["POST"])
def async_scan():
    domain = request.form.get("domain")
    if not domain:
        return jsonify({"error": "Missing domain"}), 400

    with scan_lock:
        scan_results.pop(domain, None)

    thread = threading.Thread(target=threaded_scan, args=(domain,))
    thread.start()

    return jsonify({"status": "Scan started", "domain": domain})


@app.route("/results/<domain>")
@limiter.exempt
def show_results(domain):
    with scan_lock:
        result = scan_results.get(domain)
    if not result:
        return "Results not ready or domain not found", 404

    return render_template("results.html", domain=domain, passive=result["passive"], active=result["active"])


@app.route("/scan_results/<domain>")
def get_scan_status(domain):
    with scan_lock:
        if domain in scan_results:
            return jsonify({"status": "completed", "domain": domain})
    return jsonify({"status": "in_progress"})


if __name__ == "__main__":
    app.run(debug=True)
