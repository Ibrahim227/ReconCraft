import json
import os
import re
import subprocess
import threading
from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse

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

DEFAULT_WORDLIST = os.getenv("DEFAULT_WORDLIST", "wordlists/default.txt")

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])
VALID_API_KEYS = {os.getenv("RECON_API_KEY")}

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


def sanitize_domain(domain):
    return re.sub(r'[^a-zA-Z0-9.-]', '', domain)


class Recon:
    def __init__(self, domain, output_dir="recon_output", wordlist_path=None):
        self.domain = sanitize_domain(domain)
        self.start_time = datetime.now()
        self.timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(output_dir, f"{self.domain}_{self.timestamp}")
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
        return self.run_command(["subfinder", "-d", self.domain, "-all", "-recursive"], f"{self.domain}_subs.txt")

    def assetfinder_enum(self):
        output = os.path.join(self.output_dir, f"{self.domain}_assetfinder.txt")
        self.run_command(["assetfinder", "--subs-only", self.domain, "-o", output])
        return output

    def crtsh_enum(self):
        outfile = f"{self.domain}_crtsh.txt"
        outpath = os.path.join(self.output_dir, "crtsh", outfile)
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        query = f"https://crt.sh/?q=%25.{self.domain}&output=json"

        try:
            raw_output = subprocess.check_output(f"curl -s '{query}'", shell=True, text=True)
            data = json.loads(raw_output)
            entries = sorted(set(
                entry.get("name_value", "").replace("*.", "")
                for entry in data if entry.get("name_value")
            ))
            with open(outpath, "w") as f:
                f.write("\n".join(entries))
            return outpath
        except json.JSONDecodeError:
            print("❌ crt.sh returned invalid JSON.")
            return None
        except subprocess.CalledProcessError as e:
            print(f"❌ crtsh_enum failed: {e}")
            return None

    def run_alterx(self, input_file):
        return self.run_command(["alterx", "-silent", "-w", input_file], f"{self.domain}_permuted.txt")

    def run_httpx(self, input_file):
        return self.run_command(["httpx", "-silent", "-l", input_file], f"{self.domain}_alive_subs.txt")

    def load_file_as_list(self, file_path):
        try:
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("null")]
        except FileNotFoundError:
            return []

    def run_url_crawlers(self):
        all_urls = set()
        crawlers_run = []
        tools = [
            ("gau", ["gau", self.domain]),
            ("waybackurls", ["waybackurls", self.domain]),
            ("katana", ["katana", "-u", self.domain])
        ]
        for name, cmd in tools:
            try:
                print(f"🔧 Crawling URLs with {name}...")
                result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                parsed = set(
                    self.extract_path_query(line) for line in result.splitlines() if self.extract_path_query(line))
                all_urls.update(parsed)
                crawlers_run.append(name)
            except Exception as e:
                print(f"⚠️ {name} failed: {e}")
        url_file = os.path.join(self.output_dir, f"{self.domain}_urls.txt")
        with open(url_file, "w") as f:
            f.write("\n".join(sorted(all_urls)))
        return url_file, sorted(all_urls), crawlers_run

    def extract_path_query(self, url):
        try:
            parsed = urlparse(url)
            if parsed.path or parsed.query:
                return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
        except Exception as e:
            return f"Error: {e}"

    def run_custom_scan(self, tools):
        all_subs = set()
        commands_run = []
        active = []
        urls = []

        def flatten_list(lst):
            for item in lst:
                yield item

        if "subfinder" in tools:
            path = self.subfinder_enum()
            if path:
                commands_run.append("subfinder")
                all_subs.update(flatten_list(self.load_file_as_list(path)))

        if "assetfinder" in tools:
            path = self.assetfinder_enum()
            if path:
                commands_run.append("assetfinder")
                all_subs.update(flatten_list(self.load_file_as_list(path)))

        if "crtsh" in tools:
            path = self.crtsh_enum()
            if path:
                commands_run.append("crtsh")
                all_subs.update(flatten_list(self.load_file_as_list(path)))

        all_subs_file = os.path.join(self.output_dir, f"{self.domain}_all.txt")
        with open(all_subs_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        if "alterx" in tools:
            altered = self.run_alterx(all_subs_file)
            if altered:
                commands_run.append("alterx")
                all_subs.update(flatten_list(self.load_file_as_list(altered)))

        combined_file = os.path.join(self.output_dir, f"{self.domain}_combined.txt")
        with open(combined_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        if "dnsx" in tools:
            dnsx_path = self.run_command(["dnsx", "-l", combined_file], f"{self.domain}_dnsx.txt")
            if dnsx_path:
                commands_run.append("dnsx")
                active = self.load_file_as_list(dnsx_path)
        elif "httpx" in tools:
            httpx_path = self.run_httpx(combined_file)
            if httpx_path:
                commands_run.append("httpx")
                active = self.load_file_as_list(httpx_path)

        if "urls" in tools:
            _, urls, crawlers_run = self.run_url_crawlers()
            commands_run.extend(crawlers_run)

        passive = sorted(all_subs - set(active))
        return passive, active, urls, commands_run


def run_scan(domain, tools):
    try:
        cache_key = f"{domain}:{sorted(tools)}"
        if cache_key in scan_results:
            print("🌀 Using cached result")
            return
        recon = Recon(domain)
        passive, active, urls, cmds = recon.run_custom_scan(tools)
        with scan_lock:
            scan_results[domain] = {
                "domain": domain,
                "passive": passive,
                "active": active,
                "urls": urls,
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


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'status': 'error', 'message': 'Too many requests. Please try again later.'}), 429


@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")


@app.route("/async_scan", methods=["POST"])
def async_scan():
    if request.content_type.startswith("application/json"):
        data = request.get_json()
        domain = data.get("domain", "").strip()
        tools = data.get("tools", [])
    else:
        domain = request.form.get("domain", "").strip()
        tools = request.form.getlist("tools")
        save_uploaded_file(request.files.get("wordlist_file"))

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

    return render_template("results.html", domain=domain, passive=result["passive"], active=result["active"],
                           urls=result["urls"])


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
    urls = session.get('urls', [])

    if fmt == "json":
        content = json.dumps({"passive": passive, "active": active, "urls": urls}, indent=2)
        mime, ext = "application/json", "json"
    elif fmt == "csv":
        content = "\n".join(["Subdomains:"] + passive + active)
        mime, ext = "text/csv", "csv"
    elif fmt == "live":
        content = "\n".join(active)
        mime, ext = "text/plain", "live.txt"
    elif fmt == "urls":
        content = "\n".join(urls)
        mime, ext = "text/plain", "urls.txt"
    else:
        content = "\n".join(passive + active)
        mime, ext = "text/plain", "txt"

    buffer = BytesIO(content.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, mimetype=mime, as_attachment=True, download_name=f"{domain}_subdomains.{ext}")


if __name__ == "__main__":
    app.run(debug=True)
