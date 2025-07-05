# 🕵️‍♂️ ReconCraft – Web-Based Reconnaissance Automation Tool

ReconCraft is a lightweight web-based tool designed for **automated reconnaissance in cybersecurity assessments**. It streamlines subdomain enumeration, DNS resolution, certificate transparency inspection, and live host detection — all within a user-friendly web interface.

> ⚔️ Built for bug bounty hunters, red teamers, and cybersecurity enthusiasts who want fast and efficient OSINT-powered recon.

---

## 🚀 Features

- 🔍 **Subdomain Enumeration** using tools like `subfinder`, `assetfinder`, and `crt.sh`
- 📡 **Active Host Probing** via `httpx` and `dnsx`
- 🧬 **Subdomain Permutation** using `alterx`
- 🗂️ **Historical Data Mining** via `crt.sh` API
- 🌐 **Crawled URLs Collection** using tools like `gau`, `waybackurls`, and `katana`
- 🖥️ Web UI with **Bootstrap styling**, dark mode toggle, and clipboard copying
- 📦 Deployed via **Docker** & hosted on **Render**

---

## 🧰 Tools Integrated

| Tool                                                       | Purpose                       |
|------------------------------------------------------------|-------------------------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration |
| [dnsx](https://github.com/projectdiscovery/dnsx)           | DNS resolution                |
| [httpx](https://github.com/projectdiscovery/httpx)         | HTTP probing                  |
| [crt.sh](https://crt.sh)                                   | Certificate Transparency      |
| [assetfinder](https://github.com/tomnomnom/assetfinder)    | Additional subdomains         |
| [alterx](https://github.com/projectdiscovery/alterx)       | Permutation-based fuzzing     |
| [gau](https://github.com/lc/gau)                           | URL collection from archives  |
| [waybackurls](https://github.com/tomnomnom/waybackurls)    | Archived URLs                 |
| [katana](https://github.com/projectdiscovery/katana)       | Web crawling & discovery      |


---


## 🛠️ Installation

```bash
git clone https://github.com/yourusername/reconcraft.git
cd reconcraft
```


🌍 Live Deployment
Hosted at: https://reconcraft.onrender.com

