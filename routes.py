import json
import os
import subprocess
import threading
from datetime import datetime
from io import BytesIO

from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, send_file, session, Blueprint
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev")
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])
VALID_API_KEYS = {os.getenv("RECON_API_KEY")}

scan_results = {}
scan_lock = threading.Lock()

AMASS_BIN = os.getenv("AMASS_PATH")


def save_uploaded_file(file):
    if file and file.filename:
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        return path
    return None


class Recon:
    def __init__(self, domain, output_dir="recon_output", wordlist_path=None):
        self.domain = domain
        self.start_time = datetime.now()
        self.timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(output_dir, f"{domain}_{self.timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        self.wordlist_path = wordlist_path

    def run_command(self, cmd, outfile=None):
        print(f"🔧 Running: {' '.join(cmd)}")
        if outfile:
            full_path = os.path.join(self.output_dir, outfile)
            with open(full_path, "w") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print(result.stderr.decode())
            return full_path
        else:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.decode()

    def subfinder_enum(self):
        outfile = f"{self.domain}_subfinder.txt"
        cmd = ["subfinder", "-d", self.domain, "-silent"]

        return self.run_command(cmd, outfile)

    def sublist3r_enum(self):
        outfile = f"{self.domain}_sublist3r.txt"
        cmd = ["sublist3r", "-d", self.domain, "-o", os.path.join(self.output_dir, outfile)]
        self.run_command(cmd)
        return os.path.join(self.output_dir, outfile)

    def run_alterx(self, input_file):
        outfile = f"{self.domain}_alterx.txt"
        cmd = ["alterx", "-silent", "-w", input_file]
        return self.run_command(cmd, outfile)

    def run_httpx(self, input_file):
        outfile = f"{self.domain}_httpx.txt"
        cmd = ["httpx", "-silent", "-l", input_file]
        return self.run_command(cmd, outfile)

    def load_file_as_list(self, file_path):
        try:
            with open(file_path, "r") as f:
                return sorted(set(line.strip() for line in f if line.strip()))
        except FileNotFoundError:
            return []

    def run_full_scan(self):
        subfinder_path = self.subfinder_enum()
        sublist3r_path = self.sublist3r_enum()

        all_subs = set(self.load_file_as_list(subfinder_path) + self.load_file_as_list(sublist3r_path))

        all_subs_file = os.path.join(self.output_dir, f"{self.domain}_all.txt")
        with open(all_subs_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        # Alterx for permutations
        altered_path = self.run_alterx(all_subs_file)

        # Combine all subs
        combined_subs = sorted(set(all_subs + self.load_file_as_list(altered_path)))
        combined_file = os.path.join(self.output_dir, f"{self.domain}_combined.txt")
        with open(combined_file, "w") as f:
            f.write("\n".join(combined_subs))

        # Httpx to get live domains
        httpx_path = self.run_httpx(combined_file)
        live_subs = self.load_file_as_list(httpx_path)

        return sorted(all_subs), live_subs


def execute_recon(domain, wordlist_path=None):
    recon = Recon(domain, wordlist_path=wordlist_path)
    return recon.run_full_scan()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        wordlist_path = save_uploaded_file(request.files.get("wordlist_file"))
        config_path = save_uploaded_file(request.files.get("config_file"))

        try:
            passive, active = execute_recon(domain, wordlist_path)
        except Exception as e:
            return f"Scan failed: {str(e)}", 500

        session['domain'] = domain
        session['passive_subdomains'] = passive
        session['active_subdomains'] = active

        return render_template("results.html", domain=domain, passive=passive, active=active)

    return render_template("index.html")

#
# @app.route("/api/recon", methods=["POST"])
# @limiter.exempt
# def api_recon():
#     api_key = request.headers.get("X-API-KEY")
#     if api_key not in VALID_API_KEYS:
#         abort(403, "Forbidden: Invalid API Key")
#
#     data = request.json
#     domain = data.get("domain")
#     wordlist = data.get("wordlist_file")
#     config = data.get("config_file")
#
#     try:
#         passive, active = execute_recon(domain, wordlist)
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#
#     return jsonify({"domain": domain, "passive": passive, "active": active})


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
