#!/bin/bash
set -e

echo "[+] Installing Golang and recon tools..."

apt-get update && apt-get install -y golang curl git

export GOPATH="/go"
export PATH="$PATH:$GOPATH/bin"

mkdir -p "$GOPATH/bin"

# Install tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
go install github.com/tomnomnom/assetfinder@latest || true
go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
go install github.com/tomnomnom/waybackurls@latest || true
go install github.com/lc/gau/v2/cmd/gau@latest || true
go install github.com/tomnomnom/unfurl@latest || true
go install github.com/tomnomnom/qsreplace@latest || true
go install github.com/hakluke/hakrawler@latest || true
go install github.com/projectdiscovery/katana/cmd/katana@latest || true
go install github.com/jaeles-project/gospider@latest || true
# shellcheck disable=SC2015
git clone https://github.com/projectdiscovery/alterx.git && cd alterx/v2/cmd/alterx && go install . || true



# Copy binaries to system PATH
cp "$GOPATH/bin/"* /usr/local/bin/

echo "[+] Go tools installed to /usr/local/bin"
