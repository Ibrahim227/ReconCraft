import os
import subprocess
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from io import StringIO

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "uploads"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class AmassRecon:
    def __init__(self, domain, output_dir="recon_output", wordlist_path=None, config_path=None):
        self.domain = domain
        self.output_dir = output_dir
        self.wordlist_path = wordlist_path
        self.config_path = config_path
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)
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

    def load_subdomains_as_list(self, filepath):
        print(f"Loading subdomains from: {filepath}")
        with open(filepath) as f:
            return sorted(set(line.strip() for line in f if line.strip()))


# Flask routes
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
        recon.intel()
        passive_json = recon.passive_enum()
        active_json = recon.active_enum()

        # Debugging output
        print(f"Passive JSON output: {passive_json}")
        print(f"Active JSON output: {active_json}")

        passive_subs = recon.parse_json_output(os.path.basename(passive_json))
        active_subs = recon.parse_json_output(os.path.basename(active_json))

        # Debugging output
        print(f"Passive subdomains: {passive_subs}")
        print(f"Active subdomains: {active_subs}")

        return render_template("results.html", domain=domain, passive=passive_subs, active=active_subs)
    return render_template("index.html")


@app.route("/api/recon", methods=["POST"])
def api_recon():
    data = request.json
    domain = data.get("domain")
    wordlist = data.get("wordlist_file")
    config = data.get("config_file")
    recon = AmassRecon(domain, wordlist_path=wordlist, config_path=config)
    recon.intel()
    passive_json = recon.passive_enum()
    active_json = recon.active_enum()
    passive_subs = recon.parse_json_output(os.path.basename(passive_json))
    active_subs = recon.parse_json_output(os.path.basename(active_json))
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

    buffer = StringIO(content)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype=mime,
        as_attachment=True,
        download_name=f"{domain}_subdomains.{ext}"
    )


if __name__ != "__main__":
    application = app

if __name__ == "__main__":
    app.run(debug=True)
