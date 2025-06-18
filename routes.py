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
        return self.run_command(["subfinder", "-d", self.domain, "-all", "-recursive"], f"{self.domain}_subs.txt")

    def assetfinder_enum(self):
        output = os.path.join(self.output_dir, f"{self.domain}_assetfinder.txt")
        self.run_command(["assetfinder", "--subs-only", self.domain, "-o", output])
        return output

    def run_alterx(self, input_file):
        return self.run_command(["alterx", "-silent", "-w", input_file], f"{self.domain}_permuted.txt")

    def run_dnsx(self, input_file):
        return self.run_command(["dnsx", "-silent", "-l", input_file], f"{self.domain}_dnsx_resolved.txt")

    def run_httpx(self, input_file):
        return self.run_command(["httpx", "-l", input_file, "-title", "-tech-detect", "-status-code", "-silent"],
                                f"{self.domain}_alive_subs.txt")

    # Url crawling
    def run_gau(self):
        """Fetch URLs from gau (GetAllUrls)"""
        outfile = f"{self.domain}_gau.txt"
        cmd = ["gau", "--subs", self.domain]
        return self.run_command(cmd, outfile)

    def run_waybackurls(self):
        """Fetch URLs from waybackurls (requires stdin input)"""
        outfile = f"{self.domain}_waybackurls.txt"
        full_path = os.path.join(self.output_dir, outfile)
        try:
            with open(full_path, "w") as f:
                proc = subprocess.Popen(["waybackurls"], stdin=subprocess.PIPE, stdout=f, stderr=subprocess.PIPE)
                proc.communicate(input=self.domain.encode())
            return full_path
        except Exception as e:
            print(f"❌ Failed to run waybackurls: {e}")
            return None

    def run_katana(self):
        """Run katana to crawl URLs (passive mode only, if needed)"""
        outfile = f"{self.domain}_katana.txt"
        cmd = ["katana", "-u", f"https://{self.domain}", "-d 5", "-kf", "-jc", "-fx", "-o",
               os.path.join(self.output_dir, outfile)]
        return self.run_command(cmd)

    def run_url_crawlers(self):
        urls = set()
        crawlers_run = []

        for tool_func, label in [(self.run_gau, "gau"), (self.run_waybackurls, "waybackurls"),
                                 (self.run_katana, "katana")]:
            path = tool_func()
            if path:
                crawlers_run.append(label)
                urls.update(self.load_file_as_list(path))

        filtered_urls = sorted(set(self._filter_urls(urls)))
        output_path = os.path.join(self.output_dir, f"{self.domain}_all_urls.txt")
        with open(output_path, "w") as f:
            f.write("\n".join(filtered_urls))

        return output_path, filtered_urls, crawlers_run

    def _filter_urls(self, urls):
        seen = set()
        for url in urls:
            base = url.split("?")[0]
            if base not in seen:
                seen.add(base)
                yield url

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
        urls = []

        def flatten_list(lst):
            for item in lst:
                yield item

        # Subdomain enumeration
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

        # Save all subs to file
        all_subs_file = os.path.join(self.output_dir, f"{self.domain}_all.txt")
        with open(all_subs_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        # Permutation
        if "alterx" in tools:
            altered = self.run_alterx(all_subs_file)
            if altered:
                commands_run.append("alterx")
                all_subs.update(flatten_list(self.load_file_as_list(altered)))

        # Save combined list
        combined_file = os.path.join(self.output_dir, f"{self.domain}_combined.txt")
        with open(combined_file, "w") as f:
            f.write("\n".join(sorted(all_subs)))

        # DNS resolution
        if "dnsx" in tools:
            dnsx_path = self.run_dnsx(combined_file)
            if dnsx_path:
                commands_run.append("dnsx")
                active = self.load_file_as_list(dnsx_path)

        # HTTP probing
        if "httpx" in tools:
            httpx_path = self.run_httpx(combined_file)
            if httpx_path:
                commands_run.append("httpx")
                active = self.load_file_as_list(httpx_path)

        # URL Crawling (optional)
        if "urls" in tools:
            _, urls, crawlers_run = self.run_url_crawlers()
            commands_run.extend(crawlers_run)

        passive = sorted(all_subs - set(active))
        return passive, active, urls, commands_run


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
        selected_tools = request.form.getlist("tools") or ["subfinder", "assetfinder"]

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
