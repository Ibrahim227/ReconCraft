import os
import subprocess
import json
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])
VALID_API_KEYS = {"your-secure-api-key"}  # Replace or load securely


class AmassRecon:
    def __init__(self, domain, output_dir="recon_output", wordlist_path=None, config_path=None):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(output_dir, f"{domain}_{self.timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        self.wordlist_path = wordlist_path
        self.config_path = config_path
        print(f"Initialized AmassRecon for domain: {self.domain}")

    def run_command(self, command, outfile=None):
        print(f"Running command: {command}")
        if outfile:
            full_path = os.path.join(self.output_dir, outfile)
            with open(full_path, "w") as f:
                result = subprocess.run(command, stdout=f, stderr=subprocess.PIPE, shell=True)
                print(f"Command completed with return code: {result.returncode}")
            return full_path
        else:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Command completed with return code: {result.returncode}")
            return result.stdout.decode("utf-8")

    def intel(self):
        cmd = f"amass intel -whois -whois-historic -ip -org -d {self.domain}"
        if self.config_path:
            cmd += f" -config {self.config_path}"
        return self.run_command(cmd, f"{self.domain}_intel.txt")

    def passive_enum(self):
        cmd = f"amass enum -passive -json"
        if self.config_path:
            cmd += f" -config {self.config_path}"
        cmd += f" -d {self.domain}"
        return self.run_command(cmd, f"{self.domain}_passive.json")

    def active_enum(self):
        cmd = f"amass enum -active -brute -json"
        if self.wordlist_path:
            cmd += f" -w {self.wordlist_path}"
        if self.config_path:
            cmd += f" -config {self.config_path}"
        cmd += f" -d {self.domain}"
        return self.run_command(cmd, f"{self.domain}_active.json")

    def parse_json_output(self, filename):
        print(f"Parsing JSON output from: {filename}")
        subs = set()
        with open(os.path.join(self.output_dir, filename)) as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if "name" in obj:
                        subs.add(obj["name"])
                except json.JSONDecodeError:
                    continue
        return sorted(subs)

    def run_full_scan(self):
        self.intel()
        passive_json = self.passive_enum()
        active_json = self.active_enum()
        passive_subs = self.parse_json_output(os.path.basename(passive_json))
        active_subs = self.parse_json_output(os.path.basename(active_json))
        return passive_subs, active_subs


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form.get("domain")
        wordlist_file = request.files.get("wordlist_file")
        wordlist_path = None
        if wordlist_file and wordlist_file.filename:
            filename = secure_filename(wordlist_file.filename)
            wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist_file.save(wordlist_path)

        config_file = request.files.get("config_file")
        config_path = None
        if config_file and config_file.filename:
            filename = secure_filename(config_file.filename)
            config_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            config_file.save(config_path)

        recon = AmassRecon(domain, wordlist_path=wordlist_path, config_path=config_path)
        passive_subs, active_subs = recon.run_full_scan()

        return render_template("results.html", domain=domain, passive=passive_subs, active=active_subs)
    return render_template("index.html")


@app.route("/api/recon", methods=["POST"])
@limiter.limit("5/minute")
def api_recon():
    api_key = request.headers.get("X-API-KEY")
    if api_key not in VALID_API_KEYS:
        abort(403, "Forbidden: Invalid API Key")

    data = request.json
    domain = data.get("domain")
    wordlist = data.get("wordlist_file")
    config = data.get("config_file")

    recon = AmassRecon(domain, wordlist_path=wordlist, config_path=config)
    passive_subs, active_subs = recon.run_full_scan()

    return jsonify({
        "domain": domain,
        "passive": passive_subs,
        "active": active_subs
    })


@app.route("/download", methods=["POST", "GET"])
def download():
    data = request.json
    subdomains = data.get("subdomains", [])
    fmt = data.get("format", "txt")
    domain = data.get("domain", "results")

    if fmt == "json":
        content = json.dumps(subdomains, indent=2)
        mime = "application/json"
        ext = "json"
    elif fmt == "csv":
        content = "subdomain\n" + "\n".join(subdomains)
        mime = "text/csv"
        ext = "csv"
    else:
        content = "\n".join(subdomains)
        mime = "text/plain"
        ext = "txt"

    buffer = BytesIO(content.encode('utf-8'))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype=mime,
        as_attachment=True,
        download_name=f"{domain}_subdomains.{ext}"
    )


def threaded_scan(recon):
    passive, active = recon.run_full_scan()
    print(f"Threaded scan finished for domain: {recon.domain}")


@app.route("/async_scan", methods=["POST"])
def async_scan():
    domain = request.form.get("domain")
    recon = AmassRecon(domain)
    thread = threading.Thread(target=threaded_scan, args=(recon,))
    thread.start()
    return jsonify({"status": "Scan started"})


if __name__ != "__main__":
    application = app

if __name__ == "__main__":
    app.run(debug=True)
