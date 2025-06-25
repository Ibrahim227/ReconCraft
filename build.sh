#!/bin/bash

echo "[+] Installing Golang and recon tools..."

apt-get update && apt-get install -y golang curl git

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# shellcheck disable=SC2016
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
# shellcheck disable=SC1090
source ~/.bashrc

echo "[+] Build complete."
