import json
import os
import subprocess
import threading
from datetime import datetime
from io import BytesIO

from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev")
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Default wordlist
DEFAULT_WORDLIST = os.getenv("DEFAULT_WORDLIST", "wordlists/default.txt")

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])
VALID_API_KEYS = {os.getenv("RECON_API_KEY")}

# In-memory store
scan_results = {}
scan_status = {}
scan_lock = threading.Lock()


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
        self.wordlist_path = wordlist_path or DEFAULT_WORDLIST

    def run_command(self, cmd, outfile=None):
        print(f"🔧 Running: {' '.join(cmd)}")
        try:
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
        except FileNotFoundError:
            print(f"❌ Tool not found: {cmd[0]}")
            return None

    def subfinder_enum(self):
        return self.run_command(["subfinder", "-d", self.domain, "-silent"], f"{self.domain}_subfinder.txt")

    def sublist3r_enum(self):
        output = os.path.join(self.output_dir, f"{self.domain}_sublist3r.txt")
        self.run_command(["sublist3r", "-d", self.domain, "-o", output])
        return output

    def run_alterx(self, input_file):
        return self.run_command(["alterx", "-silent", "-w", input_file], f"{self.domain}_alterx.txt")

    def run_httpx(self, input_file):
        return self.run_command(["httpx", "-silent", "-l", input_file], f"{self.domain}_httpx.txt")

    def load_file_as_list(self, file_path):
        try:
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def run_custom_scan(self, tools):
        all_subs = set()
        commands_run = []
        active = []

        def flatten_list(lst):
            for item in lst:
                yield item

        has_httpx = "httpx" in tools
        has_alterx = "alterx" in tools

        if has_httpx:
            if "subfinder" not in tools:
                subfinder_path = self.subfinder_enum()
                if subfinder_path:
                    commands_run.append("subfinder")
                    all_subs.update(flatten_list(self.load_file_as_list(subfinder_path)))
            if "sublist3r" not in tools:
                sublist3r_path = self.sublist3r_enum()
                if sublist3r_path:
                    commands_run.append("sublist3r")
                    all_subs.update(flatten_list(self.load_file_as_list(sublist3r_path)))

        if "subfinder" in tools:
            subfinder_path = self.subfinder_enum()
            if subfinder_path:
                commands_run.append("subfinder")
                all_subs.update(flatten_list(self.load_file_as_list(subfinder_path)))

        if "sublist3r" in tools:
            sublist3r_path = self.sublist3r_enum()
            if sublist3r_path:
                commands_run.append("sublist3r")
                all_subs.update(flatten_list(self.load_file_as_list(sublist3r_path)))

        all_subs_file = os.path.join(self.output_dir, f"{self.domain}_all.txt")
        with open(all_subs_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        if has_alterx:
            altered_path = self.run_alterx(all_subs_file)
            if altered_path:
                commands_run.append("alterx")
                all_subs.update(flatten_list(self.load_file_as_list(altered_path)))

        combined_file = os.path.join(self.output_dir, f"{self.domain}_combined.txt")
        with open(combined_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        if has_httpx:
            httpx_path = self.run_httpx(combined_file)
            if httpx_path:
                commands_run.append("httpx")
                active = self.load_file_as_list(httpx_path)

        passive = sorted(all_subs - set(active))
        return passive, active, commands_run


def run_scan(domain, tools):
    try:
        recon = Recon(domain)
        passive, active, cmds = recon.run_custom_scan(tools)
        with scan_lock:
            scan_results[domain] = {
                "domain": domain,
                "passive": passive,
                "active": active,
                "subdomains": sorted(set(passive + active))
            }
            scan_status[domain] = {
                "status": "completed",
                "commands": cmds
            }
    except Exception as e:
        with scan_lock:
            scan_status[domain] = {
                "status": "error",
                "message": str(e)
            }


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        selected_tools = request.form.getlist("tools") or ["subfinder", "sublist3r"]

        uploaded_file = request.files.get("wordlist_file")
        wordlist_path = save_uploaded_file(uploaded_file) or DEFAULT_WORDLIST

        if not domain or not selected_tools:
            return "Missing domain or tools", 400

        try:
            recon = Recon(domain, wordlist_path=wordlist_path)
            passive, active, _ = recon.run_custom_scan(selected_tools)
        except Exception as e:
            return f"Scan failed: {str(e)}", 500

        session['domain'] = domain
        session['passive_subdomains'] = passive
        session['active_subdomains'] = active

        return render_template("results.html", domain=domain, passive=passive, active=active)

    return render_template("index.html")


@app.route("/async_scan", methods=["POST"])
def async_scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    tools = data.get('tools', [])

    if not domain:
        return jsonify({'status': 'error', 'message': 'Missing domain'}), 400

    threading.Thread(target=run_scan, args=(domain, tools)).start()
    with scan_lock:
        scan_status[domain] = {'status': 'running', 'commands': []}

    return jsonify({'status': 'Scan started'})


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
        status = scan_status.get(domain, {"status": "in_progress"})
        return jsonify(status)


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


if __name__ == "__main__":
    app.run(debug=True)
