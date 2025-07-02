#!/bin/bash
set -e

echo "[+] Installing Golang and recon tools..."

apt-get update && apt-get install -y golang curl git

export GOPATH="/go"
export PATH="$PATH:$GOPATH/bin"

mkdir -p "$GOPATH/bin"

# Install tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# Copy binaries to system PATH
cp "$GOPATH/bin/"* /usr/local/bin/

echo "[+] Go tools installed to /usr/local/bin"
