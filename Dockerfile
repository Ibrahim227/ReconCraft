# Base image with Go and Python
FROM golang:1.21-buster

# Install system dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip curl git && \
    apt-get clean

# Set environment
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

# Copy and expose tools globally
RUN mkdir -p "$GOPATH/bin"

# Install all recon tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest

# Copy binaries to /usr/local/bin (makes them available globally)
RUN cp "$GOPATH/bin/"* /usr/local/bin/

# Set workdir
WORKDIR /app

# Copy your code
COPY . .

# Install Python requirements (Flask, gunicorn, etc.)
RUN pip3 install --no-cache-dir -r requirements.txt

# Expose port 5000
EXPOSE 5000

# Launch app
CMD ["gunicorn", "-b", "0.0.0.0:5000", "routes:app"]
