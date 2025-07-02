#!/bin/bash
set -e

echo "[+] Installing Golang and recon tools..."

apt-get update && apt-get install -y golang curl git

export GOPATH="/go"
export PATH="$PATH:$GOPATH/bin"

mkdir -p "$GOPATH/bin"

# Install tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Copy binaries to system PATH
cp "$GOPATH/bin/"* /usr/local/bin/

echo "[+] Go tools installed to /usr/local/bin"
